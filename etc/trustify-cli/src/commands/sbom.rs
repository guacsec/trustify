use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use serde_json::Value;

use crate::Context;
use crate::api::sbom as sbom_api;

/// Output format for SBOM list
#[derive(Clone, Default, ValueEnum)]
pub enum ListFormat {
    /// Only output the SBOM ID
    Id,
    /// Output id, name, document_id
    Name,
    /// Output id, name, document_id, ingested, published, size
    Short,
    /// Output complete JSON document
    #[default]
    Full,
}

#[derive(Subcommand)]
pub enum DuplicatesCommands {
    /// Find duplicates by namespace
    Find {
        /// Batch size for querying duplicates
        #[arg(short = 'b', long, default_value = "100")]
        batch_size: u32,

        /// Number of concurrent fetch requests (default: 4)
        #[arg(short = 'j', long, default_value = "4")]
        concurrency: usize,

        /// Output file
        #[arg(long, default_value = "duplicates.json")]
        output: Option<String>,
    },
    /// Delete duplicates
    Delete {
        /// Input file
        #[arg(long, default_value = "duplicates.json")]
        input: Option<String>,

        /// Number of concurrent delete requests (default: 8)
        #[arg(short = 'j', long, default_value = "8")]
        concurrency: usize,

        /// Perform a dry run without actually deleting
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub enum SbomCommands {
    /// Get SBOM by ID
    Get {
        /// SBOM ID
        id: String,
    },
    /// List SBOMs
    List {
        /// Query filter for SBOMs
        #[arg(long)]
        query: Option<String>,
        /// Limit the number of results
        #[arg(long)]
        limit: Option<u32>,
        /// Offset the results
        #[arg(long)]
        offset: Option<u32>,
        /// Sort the results
        /// Example: `purl:qualifiers:type:desc`
        #[arg(long)]
        sort: Option<String>,
        /// Output format: id, name, short, full (default: full)
        #[arg(long, value_enum, default_value = "full")]
        format: ListFormat,
    },
    /// Delete SBOMs
    Delete {
        /// SBOM ID
        #[arg(long)]
        id: Option<String>,

        /// Query filter for SBOMs to delete
        #[arg(long)]
        query: Option<String>,

        /// Perform a dry run without actually deleting
        #[arg(long)]
        dry_run: bool,

        /// Number of concurrent delete requests (default: 10)
        #[arg(long, default_value = "10")]
        concurrency: usize,

        /// Limit the number of SBOMs to query and delete (default: 100)
        #[arg(long, default_value = "100")]
        limit: Option<u32>,
    },
    /// Manage duplicate SBOMs
    Duplicates {
        #[command(subcommand)]
        command: DuplicatesCommands,
    },
}

impl SbomCommands {
    pub async fn run(&self, ctx: &Context) -> anyhow::Result<ExitCode> {
        match self {
            SbomCommands::Duplicates { command } => command.run(ctx).await,
            SbomCommands::Get { id } => {
                let json = sbom_api::get(&ctx.client, id).await?;
                println!("{}", json);
                Ok(ExitCode::SUCCESS)
            }
            SbomCommands::List {
                query,
                limit,
                offset,
                sort,
                format,
            } => {
                let params = sbom_api::ListParams {
                    q: query.clone(),
                    limit: *limit,
                    offset: *offset,
                    sort: sort.clone(),
                };
                let json = sbom_api::list(&ctx.client, &params).await?;
                format_list_output(&json, format)?;
                Ok(ExitCode::SUCCESS)
            }
            SbomCommands::Delete {
                id,
                query,
                dry_run,
                concurrency,
                limit,
            } => {
                if let Some(i) = id {
                    sbom_api::delete(&ctx.client, i).await?;
                    println!("Deleted SBOM ID: {}", i);
                }
                if let Some(q) = query {
                    let delete_result = sbom_api::delete_by_query(
                        &ctx.client,
                        Some(q.as_str()),
                        *dry_run,
                        *concurrency,
                        *limit,
                    )
                    .await?;
                    if *dry_run {
                        println!("[DRY-RUN] Would delete {} SBOM(s)", delete_result.total);
                    } else {
                        let mut msg = format!("Deleted {} SBOM(s)", delete_result.deleted);
                        if delete_result.skipped > 0 {
                            msg.push_str(&format!(
                                ", {} skipped (not found)",
                                delete_result.skipped
                            ));
                        }
                        if delete_result.failed > 0 {
                            msg.push_str(&format!(", {} failed", delete_result.failed));
                        }
                        msg.push_str(&format!(" out of {} total", delete_result.total));
                        println!("{}", msg);
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

impl DuplicatesCommands {
    pub async fn run(&self, ctx: &Context) -> anyhow::Result<ExitCode> {
        match self {
            DuplicatesCommands::Find {
                batch_size,
                concurrency,
                output,
            } => {
                let output_path = output
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("duplicates.json");

                // Check if output file exists
                let final_output = check_output_file(output_path);
                if final_output.is_none() {
                    eprintln!("Operation cancelled.");
                    return Ok(ExitCode::SUCCESS);
                }
                let final_output = final_output.unwrap_or("duplicates.json".to_string());

                let params = sbom_api::FindDuplicatesParams {
                    batch_size: *batch_size,
                    concurrency: *concurrency,
                };
                let groups =
                    sbom_api::find_duplicates(&ctx.client, &params, &Some(final_output.clone()))
                        .await?;
                let total_duplicates: usize = groups.iter().map(|g| g.duplicates.len()).sum();
                println!(
                    "Found {} document(s) with {} duplicate(s). Saved to {}",
                    groups.len(),
                    total_duplicates,
                    final_output
                );
                Ok(ExitCode::SUCCESS)
            }
            DuplicatesCommands::Delete {
                input,
                concurrency,
                dry_run,
            } => {
                let input_path = input
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("duplicates.json");

                let result =
                    sbom_api::delete_duplicates(&ctx.client, input_path, *concurrency, *dry_run)
                        .await?;
                if *dry_run {
                    println!("[DRY-RUN] Would delete {} duplicate(s)", result.total);
                } else {
                    let mut msg = format!("Deleted {} duplicate(s)", result.deleted);
                    if result.skipped > 0 {
                        msg.push_str(&format!(", {} skipped (not found)", result.skipped));
                    }
                    if result.failed > 0 {
                        msg.push_str(&format!(", {} failed", result.failed));
                    }
                    msg.push_str(&format!(" out of {} total", result.total));
                    println!("{}", msg);
                }
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

/// Format and print list output based on the specified format
fn format_list_output(json: &str, format: &ListFormat) -> anyhow::Result<ExitCode> {
    let parsed: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing response: {}", e);
            return Err(e.into());
        }
    };

    // The API returns { "items": [...], "total": N }
    let items = match parsed.get("items").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            // If no items array, just print the raw JSON
            println!("{}", json);
            return Ok(ExitCode::SUCCESS);
        }
    };

    match format {
        ListFormat::Full => {
            println!("{}", json);
            Ok(ExitCode::SUCCESS)
        }
        ListFormat::Id => {
            for item in items {
                if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                    println!("{}", id);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        ListFormat::Name => {
            let result: Vec<Value> = items
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "document_id": item.get("document_id")
                    })
                })
                .collect();
            let json = serde_json::to_string(&result)
                .map_err(|e| anyhow::anyhow!("Failed to serialize output: {}", e))?;
            println!("{}", json);
            Ok(ExitCode::SUCCESS)
        }
        ListFormat::Short => {
            let result: Vec<Value> = items
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "document_id": item.get("document_id"),
                        "ingested": item.get("ingested"),
                        "published": item.get("published"),
                        "size": item.get("size"),
                    })
                })
                .collect();
            let json = serde_json::to_string(&result)
                .map_err(|e| anyhow::anyhow!("Failed to serialize output: {}", e))?;
            println!("{}", json);
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Check if output file exists and prompt user for action
/// Returns None if user cancels, Some(path) with the final path to use
fn check_output_file(output_path: &str) -> Option<String> {
    let path = Path::new(output_path);

    if !path.exists() {
        return Some(output_path.to_string());
    }

    // File exists, ask user what to do
    loop {
        eprint!(
            "File '{}' already exists. Overwrite? [y]es / [n]o / [r]ename: ",
            output_path
        );
        io::stderr().flush().ok();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return None;
        }

        let input = input.trim().to_lowercase();
        match input.as_str() {
            "y" | "yes" => {
                return Some(output_path.to_string());
            }
            "n" | "no" => {
                return None;
            }
            "r" | "rename" => {
                // Generate a new filename
                let new_name = generate_unique_filename(output_path);
                eprintln!("Using: {}", new_name);
                return Some(new_name);
            }
            _ => {
                eprintln!("Please enter 'y', 'n', or 'r'");
            }
        }
    }
}

/// Generate a unique filename by appending a number
fn generate_unique_filename(base_path: &str) -> String {
    let path = Path::new(base_path);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("duplicates");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("json");
    let parent = path.parent().and_then(|p| p.to_str()).unwrap_or("");

    for i in 1..1000 {
        let new_name = if parent.is_empty() {
            format!("{}_{}.{}", stem, i, ext)
        } else {
            format!("{}/{}_{}.{}", parent, stem, i, ext)
        };

        if !Path::new(&new_name).exists() {
            return new_name;
        }
    }

    // Fallback with timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if parent.is_empty() {
        format!("{}_{}.{}", stem, timestamp, ext)
    } else {
        format!("{}/{}_{}.{}", parent, stem, timestamp, ext)
    }
}
