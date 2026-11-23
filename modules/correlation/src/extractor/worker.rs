use crate::{
    extractor::Extractors,
    service::{detail, extraction, freshness, projection, tuning::WorkerConfig},
};
use sea_orm::DatabaseConnection;
use std::time::{Duration, Instant};
use tokio::{sync::broadcast, task::JoinSet};
use trustify_common::db::{self, change::ChangeBroadcaster};

/// How often an idle worker removes unreferenced evidence details, see [`detail::run_step`].
const DETAIL_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

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
    let connection: &DatabaseConnection = &db;
    let extractors = Extractors::default()
        .with_match_batch(config.match_batch)
        .with_detail_connection(connection.clone());
    let mut cleaned: Option<Instant> = None;
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
                Duration::ZERO
            } else {
                Duration::from_secs(1)
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
        // only when idle, and skipped while any extraction runs
        if !pending && cleaned.is_none_or(|at| at.elapsed() >= DETAIL_CLEANUP_INTERVAL) {
            match detail::run_step(&db).await {
                Ok(Some(removed)) => {
                    tracing::debug!(removed, "removed unreferenced evidence details");
                    cleaned = Some(Instant::now());
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "evidence detail cleanup failed");
                    cleaned = Some(Instant::now());
                }
            }
        }
    }
    Ok(())
}
