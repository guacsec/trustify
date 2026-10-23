//! Durable ingestion backlog. Notifications only wake the worker; PostgreSQL owns the work.
use crate::{error::Error, extractor::Extractors, model::ExtractionLag, service::freshness};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, FromQueryResult, Statement, TransactionTrait,
};
use time::OffsetDateTime;
use trustify_common::db;
use uuid::Uuid;

#[derive(FromQueryResult)]
struct Lag {
    pending_advisories: i64,
    pending_sboms: i64,
    failed: i64,
    oldest_pending_at: Option<OffsetDateTime>,
}

pub async fn lag(tx: &DatabaseTransaction) -> Result<ExtractionLag, Error> {
    let row = tx
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) FILTER (WHERE entity_type = 'advisory') pending_advisories, \
             count(*) FILTER (WHERE entity_type = 'sbom') pending_sboms, \
             count(*) FILTER (WHERE attempts > 0) failed, min(queued_at) oldest_pending_at \
             FROM correlation_extraction_queue",
        ))
        .await?
        .ok_or_else(|| sea_orm::DbErr::Custom("missing extraction lag".into()))?;
    let row = Lag::from_query_result(&row, "")?;
    Ok(ExtractionLag {
        pending_advisories: row.pending_advisories as u64,
        pending_sboms: row.pending_sboms as u64,
        failed: row.failed as u64,
        oldest_pending_at: row.oldest_pending_at,
    })
}

/// Claim one event across all server instances. The queue row remains visible to
/// readers until evidence commits, and a crash rolls back the acknowledgement.
pub async fn run_step(db: &db::ReadWrite, extractors: &Extractors) -> Result<bool, Error> {
    let tx = db.begin().await?;
    freshness::lock_revision(&tx).await?;
    let Some(row) = tx
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT id, entity_type, entity_id FROM correlation_extraction_queue \
             WHERE retry_at <= now() ORDER BY retry_at, queued_at, id \
             LIMIT 1 FOR UPDATE SKIP LOCKED",
        ))
        .await?
    else {
        return Ok(false);
    };
    let id: Uuid = row.try_get("", "id")?;
    let entity_type: String = row.try_get("", "entity_type")?;
    let entity_id: Uuid = row.try_get("", "entity_id")?;

    // Keep the claim while rolling back evidence on failure. Other workers can
    // claim different rows; failed events cannot block the rest of an import.
    let work = tx.begin().await?;
    let result = extract(&work, extractors, &entity_type, entity_id).await;
    match result {
        Ok(()) => {
            work.commit().await?;
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "DELETE FROM correlation_extraction_queue WHERE id = $1",
                vec![id.into()],
            ))
            .await?;
        }
        Err(err) => {
            work.rollback().await?;
            tracing::warn!(%entity_type, %entity_id, error = %err, "correlation extraction failed; retrying in 30 seconds");
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE correlation_extraction_queue SET attempts = attempts + 1, \
                 retry_at = clock_timestamp() + interval '30 seconds' WHERE id = $1",
                vec![id.into()],
            ))
            .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

async fn extract(
    tx: &DatabaseTransaction,
    extractors: &Extractors,
    entity_type: &str,
    entity_id: Uuid,
) -> Result<(), Error> {
    // A document deleted before processing has no remaining extraction work.
    // Lock its parent while extracting, matching the evidence writers' lock order.
    let query = match entity_type {
        "sbom" => "SELECT sbom_id FROM sbom WHERE sbom_id = $1 FOR KEY SHARE",
        "advisory" => "SELECT id FROM advisory WHERE id = $1 FOR KEY SHARE",
        _ => return Err(Error::BadRequest("Unknown extraction entity type".into())),
    };
    if tx
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            query,
            vec![entity_id.into()],
        ))
        .await?
        .is_none()
    {
        return Ok(());
    }
    match entity_type {
        "sbom" => freshness::refresh_sbom(extractors, entity_id, tx).await?,
        "advisory" => {
            extractors.extract_for_advisory(entity_id, tx).await?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
