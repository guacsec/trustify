use crate::{
    extractor::Extractors,
    service::{extraction, freshness, projection, tuning::WorkerConfig},
};
use tokio::{sync::broadcast, task::JoinSet};
use trustify_common::db::{self, change::ChangeBroadcaster};

/// Run [`WorkerConfig::workers`] workers in parallel, each in its own task, until one fails.
///
/// The workers claim different work: advisories of the extraction queue, documents of the refresh
/// job, and SBOMs to compute verdicts for. Dropping the future stops all of them.
pub async fn run_extraction_workers(
    broadcaster: ChangeBroadcaster,
    db: db::ReadWrite,
    config: WorkerConfig,
) -> anyhow::Result<()> {
    let mut workers = JoinSet::new();
    for _ in 0..config.workers.get() {
        workers.spawn(run_extraction_worker(
            broadcaster.clone(),
            db.clone(),
            config.clone(),
        ));
    }
    while let Some(result) = workers.join_next().await {
        result??;
    }
    Ok(())
}

/// Drain durable ingestion work and requested refresh jobs. Notifications are
/// wakeups only: missed events and restarts cannot lose queued extraction work.
pub async fn run_extraction_worker(
    broadcaster: ChangeBroadcaster,
    db: db::ReadWrite,
    config: WorkerConfig,
) -> anyhow::Result<()> {
    let extractors = Extractors::default().with_match_batch(config.match_batch);
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
        pending = match extraction::run_step(&db, &extractors, &config).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(error = %err, "correlation extraction worker failed");
                false
            }
        };
        // Give requested refreshes a turn even during a continuous import.
        pending |= match freshness::run_step(&db, &extractors, &config).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(error = %err, "correlation refresh worker failed");
                false
            }
        };
        pending |= match projection::run_step(&db, &config).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(error = %err, "verdict worker failed");
                false
            }
        };
    }
    Ok(())
}
