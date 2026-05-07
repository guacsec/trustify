use super::client::{ApiClient, ApiError};
use crate::common::{
    DeleteEntry, DeleteResult, ListParams, PruneParams, build_prune_query, delete_entries,
    new_delete_result,
};

const ADVISORY_PATH: &str = "/v3/advisory";

pub async fn list(client: &ApiClient, params: &ListParams) -> Result<String, ApiError> {
    client.get_with_query(ADVISORY_PATH, params).await
}

pub async fn prune(client: &ApiClient, params: &PruneParams) -> Result<DeleteResult, ApiError> {
    let (_query, list_params) = build_prune_query(params);

    log::info!(
        "Pruning advisories with query: {}",
        list_params.q.as_deref().unwrap_or("")
    );

    let response = list(client, &list_params).await?;
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| ApiError::InternalError(format!("Failed to parse response: {}", e)))?;

    let items = parsed
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ApiError::InternalError("No items in response".to_string()))?;

    let total = items.len() as u32;

    let entries: Vec<DeleteEntry> = items
        .iter()
        .filter_map(|item| {
            let id = item.get("uuid").and_then(|v| v.as_str())?;

            let identifier = item
                .get("identifier")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            Some(DeleteEntry {
                id: id.to_string(),
                identifier: identifier.to_string(),
            })
        })
        .collect();

    if params.dry_run {
        return Ok(new_delete_result(total));
    }

    delete_entries(client, ADVISORY_PATH, entries, params.concurrency).await
}
