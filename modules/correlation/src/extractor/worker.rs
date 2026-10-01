use crate::{error::Error, extractor::Extractors};
use sea_orm::TransactionTrait;
use tokio::sync::broadcast;
use trustify_common::db::{
    self,
    change::{ChangeBroadcaster, ChangeEntity, ChangeEntry, ChangeOperation},
};

/// Spawns the correlation extraction worker as a background task.
///
/// Subscribes to the `ChangeBroadcaster` and runs all registered extractors
/// when SBOMs or advisories are ingested.
pub async fn run_extraction_worker(
    broadcaster: ChangeBroadcaster,
    db: db::ReadWrite,
) -> anyhow::Result<()> {
    let extractors = Extractors::default();
    let mut rx = broadcaster.subscribe();
    loop {
        match rx.recv().await {
            Ok(entry) => {
                if let Err(err) = handle_change(&entry, &extractors, &db).await {
                    tracing::warn!(
                        entity = ?entry.r#type,
                        id = ?entry.id,
                        error = %err,
                        "correlation extraction failed"
                    );
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "correlation extraction worker lagged");
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::info!("correlation extraction worker stopping: channel closed");
                break;
            }
        }
    }
    Ok(())
}

async fn handle_change(
    entry: &ChangeEntry,
    extractors: &Extractors,
    db: &db::ReadWrite,
) -> Result<(), Error> {
    if entry.operation != ChangeOperation::Added {
        return Ok(());
    }

    let Some(entity_id) = entry.id else {
        return Ok(());
    };

    let tx = db.begin().await?;
    match entry.r#type {
        ChangeEntity::Sbom => extractors.extract_for_sbom(entity_id, &tx).await?,
        ChangeEntity::Advisory => extractors.extract_for_advisory(entity_id, &tx).await?,
    };
    tx.commit().await?;

    Ok(())
}
