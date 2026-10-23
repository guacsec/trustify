use crate::{
    extractor::Extractors,
    service::{extraction, freshness},
};
use tokio::sync::broadcast;
use trustify_common::db::{self, change::ChangeBroadcaster};

/// Drain durable ingestion work and requested refresh jobs. Notifications are
/// wakeups only: missed events and restarts cannot lose queued extraction work.
pub async fn run_extraction_worker(
    broadcaster: ChangeBroadcaster,
    db: db::ReadWrite,
) -> anyhow::Result<()> {
    let extractors = Extractors::default();
    let mut rx = broadcaster.subscribe();
    // Drain work left by an earlier process immediately on startup.
    let mut pending = true;
    loop {
        tokio::select! {
            entry = rx.recv() => match entry {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {},
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = tokio::time::sleep(if pending {
                std::time::Duration::ZERO
            } else {
                std::time::Duration::from_secs(1)
            }) => {},
        }
        pending = match extraction::run_step(&db, &extractors).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(error = %err, "correlation extraction worker failed");
                false
            }
        };
        // Give requested refreshes a turn even during a continuous import.
        pending |= match freshness::run_step(&db, &extractors).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(error = %err, "correlation refresh worker failed");
                false
            }
        };
    }
    Ok(())
}
