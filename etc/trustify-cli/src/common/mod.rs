use std::sync::Arc;

use chrono::{DateTime, Duration, Local};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::api::client::{ApiClient, ApiError};

/// Build query string and list params from prune parameters
pub fn build_prune_query(params: &PruneParams) -> (String, ListParams) {
    let mut query = params.q.as_deref().unwrap_or("").to_string();

    if let Some(d) = params.published_before.as_ref() {
        query.push_str(&format!("&published<{}", d.to_rfc3339()));
    }

    if let Some(older_than) = params.older_than {
        let older_than_time = Local::now() - Duration::days(older_than);
        query.push_str(&format!("&ingested<{}", older_than_time.to_rfc3339()));
    }

    if let Some(labels) = &params.label {
        for l in labels.iter() {
            query.push_str(&format!("&labels:{}", l));
        }
    }

    let (offset, sort) = match params.keep_latest {
        Some(v) => (Some(v), Some("ingested:desc".to_string())),
        None => (None, None),
    };

    let list_params = ListParams {
        q: Some(query.clone()),
        limit: params.limit,
        offset,
        sort,
    };

    (query, list_params)
}

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

#[derive(Default, Serialize)]
pub struct PruneParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_before: Option<DateTime<Local>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_than: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_latest: Option<u32>,
    pub dry_run: bool,
    pub concurrency: usize,
}

#[derive(Clone, Debug)]
pub struct DeleteEntry {
    pub id: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResult {
    pub deleted: Vec<DeletedResult>,
    pub deleted_total: u32,
    pub skipped: Vec<SkippedResult>,
    pub skipped_total: u32,
    pub failed: Vec<FailedResult>,
    pub failed_total: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedResult {
    pub id: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedResult {
    pub id: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedResult {
    pub id: String,
    pub identifier: String,
    pub error: String,
}

pub async fn delete_entries(
    client: &ApiClient,
    base_path: &str,
    entries: Vec<DeleteEntry>,
    concurrency: usize,
) -> Result<DeleteResult, ApiError> {
    let total_count = entries.len() as u32;

    eprintln!(
        "Deleting {} entries with {} concurrent requests...\n",
        total_count, concurrency
    );

    let progress = ProgressBar::new(total_count as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")?
            .progress_chars("█▓░"),
    );

    let deleted = Arc::new(Mutex::new(Vec::new()));
    let skipped = Arc::new(Mutex::new(Vec::new()));
    let failed = Arc::new(Mutex::new(Vec::new()));

    stream::iter(entries)
        .for_each_concurrent(concurrency, |entry| {
            let client = client.clone();
            let deleted = Arc::clone(&deleted);
            let skipped = Arc::clone(&skipped);
            let failed = Arc::clone(&failed);
            let progress = progress.clone();
            let base_path = base_path.to_string();

            async move {
                let path = format!("{}/{}", base_path, entry.id);
                match client.delete(&path).await {
                    Ok(_) => {
                        let mut deleted_list = deleted.lock().await;
                        deleted_list.push(DeletedResult {
                            id: entry.id.clone(),
                            identifier: entry.identifier.clone(),
                        });
                    }
                    Err(ApiError::HttpError(404, _)) => {
                        let mut skipped_list = skipped.lock().await;
                        skipped_list.push(SkippedResult {
                            id: entry.id.clone(),
                            identifier: entry.identifier.clone(),
                        });
                    }
                    Err(e) => {
                        let mut failed_list = failed.lock().await;
                        failed_list.push(FailedResult {
                            id: entry.id.clone(),
                            identifier: entry.identifier.clone(),
                            error: e.to_string(),
                        });
                        progress.println(format!(
                            "Failed to delete {} (identifier: {}): {}",
                            entry.id, entry.identifier, e
                        ));
                    }
                }
                progress.inc(1);
            }
        })
        .await;

    progress.finish_with_message("complete");

    let deleted_list = deleted.lock().await;
    let skipped_list = skipped.lock().await;
    let failed_list = failed.lock().await;

    Ok(DeleteResult {
        deleted: deleted_list.clone(),
        deleted_total: deleted_list.len() as u32,
        skipped: skipped_list.clone(),
        skipped_total: skipped_list.len() as u32,
        failed: failed_list.clone(),
        failed_total: failed_list.len() as u32,
        total: total_count,
    })
}

pub fn new_delete_result(total: u32) -> DeleteResult {
    DeleteResult {
        deleted: vec![],
        deleted_total: 0,
        skipped: vec![],
        skipped_total: 0,
        failed: vec![],
        failed_total: 0,
        total,
    }
}
