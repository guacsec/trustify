use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use futures::future::join_all;
use futures::stream::{self, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use super::client::{ApiClient, ApiError};

const SBOM_PATH: &str = "/v2/sbom";

/// Query parameters for listing SBOMs
#[derive(Default, Serialize)]
pub struct ListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
}

/// Parameters for find duplicates
pub struct FindDuplicatesParams {
    pub batch_size: u32,
    pub concurrency: usize,
}

/// SBOM entry for duplicate detection
#[derive(Debug, Clone)]
struct SbomEntry {
    id: String,
    document_id: String,
    published: Option<String>,
}

/// Duplicate group output format
#[derive(Debug, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub document_id: String,
    pub published: Option<String>,
    pub id: String,
    pub duplicates: Vec<String>,
}

/// Get SBOM by ID - returns raw JSON
pub async fn get(client: &ApiClient, id: &str) -> Result<String, ApiError> {
    let path = format!("{}/{}", SBOM_PATH, id);
    client.get(&path).await
}

/// List SBOMs with optional query parameters - returns raw JSON
pub async fn list(client: &ApiClient, params: &ListParams) -> Result<String, ApiError> {
    client.get_with_query(SBOM_PATH, params).await
}

/// Fetch a single page and extract SBOM entries
async fn fetch_page(
    client: &ApiClient,
    batch_size: u32,
    offset: u32,
) -> Result<Vec<SbomEntry>, ApiError> {
    let list_params = ListParams {
        q: None,
        limit: Some(batch_size),
        offset: Some(offset),
        sort: None,
    };

    let response = list(client, &list_params).await?;
    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| ApiError::InternalError(format!("Failed to parse response: {}", e)))?;

    let items = parsed
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ApiError::InternalError("No items in response".to_string()))?;

    let entries: Vec<SbomEntry> = items
        .iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(|v| v.as_str())?.to_string();
            let document_id = item
                .get("document_id")
                .and_then(|v| v.as_str())?
                .to_string();
            let published = item
                .get("published")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if document_id.is_empty() {
                None
            } else {
                Some(SbomEntry {
                    id,
                    document_id,
                    published,
                })
            }
        })
        .collect();

    Ok(entries)
}

/// Worker that fetches assigned pages sequentially
async fn fetch_worker(
    worker_id: usize,
    client: ApiClient,
    pages: Vec<u32>,
    batch_size: u32,
    progress_bar: ProgressBar,
    results: Arc<Mutex<Vec<SbomEntry>>>,
) {
    let mut fetched: u64 = 0;

    for offset in pages {
        match fetch_page(&client, batch_size, offset).await {
            Ok(entries) => {
                fetched += entries.len() as u64;
                progress_bar.set_position(fetched);
                results.lock().await.extend(entries);
            }
            Err(e) => {
                progress_bar.println(format!(
                    "Worker {}: Error at offset {}: {}",
                    worker_id, offset, e
                ));
            }
        }
    }

    progress_bar.finish_with_message("done");
}

/// Find duplicate SBOMs by document_id and save to file
pub async fn find_duplicates(
    client: &ApiClient,
    params: &FindDuplicatesParams,
    output_file: &Option<String>,
) -> Result<Vec<DuplicateGroup>, ApiError> {
    let batch_size = params.batch_size;
    let concurrency = params.concurrency;

    // First, get the total count
    let first_page = list(
        client,
        &ListParams {
            q: None,
            limit: Some(1),
            offset: Some(0),
            sort: None,
        },
    )
    .await?;

    let parsed: Value = serde_json::from_str(&first_page)
        .map_err(|e| ApiError::InternalError(format!("Failed to parse response: {}", e)))?;

    let total = parsed.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if total == 0 {
        eprintln!("No SBOMs found");
        return Ok(Vec::new());
    }

    eprintln!("Fetching {} SBOMs with {} workers...\n", total, concurrency);

    // Calculate page offsets
    let num_pages = total.div_ceil(batch_size);
    let all_offsets: Vec<u32> = (0..num_pages).map(|i| i * batch_size).collect();

    // Distribute pages evenly among workers
    let mut worker_pages: Vec<Vec<u32>> = vec![Vec::new(); concurrency];
    for (i, offset) in all_offsets.into_iter().enumerate() {
        worker_pages[i % concurrency].push(offset);
    }

    // Calculate how many SBOMs each worker will fetch
    let worker_counts: Vec<u64> = worker_pages
        .iter()
        .map(|pages| {
            pages
                .iter()
                .map(|&offset| {
                    let remaining = total.saturating_sub(offset);
                    remaining.min(batch_size) as u64
                })
                .sum()
        })
        .collect();

    // Set up progress bars
    let multi_progress = MultiProgress::new();
    let style = ProgressStyle::default_bar()
        .template("{prefix:>12} [{bar:30.cyan/blue}] {pos}/{len} ({percent}%)")?
        .progress_chars("█▓░");

    let results: Arc<Mutex<Vec<SbomEntry>>> = Arc::new(Mutex::new(Vec::new()));

    // Spawn workers
    let mut handles = Vec::new();
    for (worker_id, pages) in worker_pages.into_iter().enumerate() {
        if pages.is_empty() {
            continue;
        }

        let worker_total = worker_counts[worker_id];
        let pb = multi_progress.add(ProgressBar::new(worker_total));
        pb.set_style(style.clone());
        pb.set_prefix(format!("Worker {}", worker_id + 1));

        let client = client.clone();
        let results = Arc::clone(&results);

        handles.push(tokio::spawn(fetch_worker(
            worker_id + 1,
            client,
            pages,
            batch_size,
            pb,
            results,
        )));
    }

    // Wait for all workers to complete
    join_all(handles).await;

    let all_entries = Arc::try_unwrap(results)
        .map_err(|_| ApiError::InternalError("Failed to unwrap entries".to_string()))?
        .into_inner();

    eprintln!("\nProcessing {} SBOMs for duplicates...", all_entries.len());

    // Group by document_id
    let mut groups: HashMap<String, Vec<SbomEntry>> = HashMap::new();
    for entry in all_entries {
        groups
            .entry(entry.document_id.clone())
            .or_default()
            .push(entry);
    }

    // Find duplicates (groups with more than one entry)
    let mut duplicate_groups: Vec<DuplicateGroup> = Vec::new();

    for (document_id, mut entries) in groups {
        if entries.len() <= 1 {
            continue;
        }

        // Sort by published date descending (most recent first)
        entries.sort_by(|a, b| match (&b.published, &a.published) {
            (Some(b_pub), Some(a_pub)) => b_pub.cmp(a_pub),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        let most_recent = entries.remove(0);
        let duplicates: Vec<String> = entries.into_iter().map(|e| e.id).collect();

        duplicate_groups.push(DuplicateGroup {
            document_id,
            published: most_recent.published,
            id: most_recent.id,
            duplicates,
        });
    }

    eprintln!(
        "Found {} document(s) with duplicates",
        duplicate_groups.len()
    );

    // Save to file
    let output_path = output_file
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("duplicates.json");

    let json = serde_json::to_string_pretty(&duplicate_groups)
        .map_err(|e| ApiError::InternalError(format!("Failed to serialize results: {}", e)))?;

    let mut file = File::create(output_path)
        .map_err(|e| ApiError::InternalError(format!("Failed to create output file: {}", e)))?;

    file.write_all(json.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("Failed to write to file: {}", e)))?;

    Ok(duplicate_groups)
}

/// Delete an SBOM by ID
pub async fn delete(client: &ApiClient, id: &str) -> Result<(), ApiError> {
    let path = format!("{}/{}", SBOM_PATH, id);
    client.delete(&path).await?;
    Ok(())
}

/// Result of deleting duplicates
pub struct DeleteDuplicatesResult {
    pub deleted: u32,
    pub skipped: u32,
    pub failed: u32,
    pub total: u32,
}

/// Entry to delete with its document_id for logging
#[derive(Clone)]
struct DeleteEntry {
    id: String,
    document_id: String,
}

/// Delete duplicates from a file with progress bar
pub async fn delete_duplicates(
    client: &ApiClient,
    input_file: &str,
    concurrency: usize,
    dry_run: bool,
) -> Result<DeleteDuplicatesResult, ApiError> {
    // Check if file exists
    let path = Path::new(input_file);
    if !path.exists() {
        return Err(ApiError::InternalError(format!(
            "Input file not found: {}",
            input_file
        )));
    }

    // Read and parse the file
    let file = File::open(path)
        .map_err(|e| ApiError::InternalError(format!("Failed to open input file: {}", e)))?;
    let reader = BufReader::new(file);

    let groups: Vec<DuplicateGroup> = serde_json::from_reader(reader)
        .map_err(|e| ApiError::InternalError(format!("Failed to parse input file: {}", e)))?;

    // Collect all duplicate entries to delete
    let entries: Vec<DeleteEntry> = groups
        .iter()
        .flat_map(|group| {
            group.duplicates.iter().map(|id| DeleteEntry {
                id: id.clone(),
                document_id: group.document_id.clone(),
            })
        })
        .collect();

    let total = entries.len() as u32;

    if dry_run {
        for entry in &entries {
            eprintln!(
                "[DRY-RUN] Would delete: {} (document_id: {})",
                entry.id, entry.document_id
            );
        }
        return Ok(DeleteDuplicatesResult {
            deleted: 0,
            skipped: 0,
            failed: 0,
            total,
        });
    }

    eprintln!(
        "Deleting {} duplicates with {} concurrent requests...\n",
        total, concurrency
    );

    // Set up progress bar
    let progress = ProgressBar::new(total as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")?
            .progress_chars("█▓░"),
    );

    let deleted = Arc::new(AtomicU32::new(0));
    let skipped = Arc::new(AtomicU32::new(0));
    let failed = Arc::new(AtomicU32::new(0));

    stream::iter(entries)
        .for_each_concurrent(concurrency, |entry| {
            let client = client.clone();
            let deleted = Arc::clone(&deleted);
            let skipped = Arc::clone(&skipped);
            let failed = Arc::clone(&failed);
            let progress = progress.clone();
            async move {
                match delete(&client, &entry.id).await {
                    Ok(_) => {
                        deleted.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(ApiError::NotFound(_)) => {
                        // SBOM already deleted or doesn't exist - skip silently
                        skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        progress.println(format!(
                            "Failed to delete {} (document_id: {}): {}",
                            entry.id, entry.document_id, e
                        ));
                    }
                }
                progress.inc(1);
            }
        })
        .await;

    progress.finish_with_message("complete");

    Ok(DeleteDuplicatesResult {
        deleted: deleted.load(Ordering::Relaxed),
        skipped: skipped.load(Ordering::Relaxed),
        failed: failed.load(Ordering::Relaxed),
        total,
    })
}
