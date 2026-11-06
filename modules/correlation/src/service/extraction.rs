//! Durable advisory ingestion backlog. Notifications only wake the worker; PostgreSQL owns
//! the work. SBOMs are extracted by the automatically scheduled refresh jobs instead.
use crate::{
    error::Error,
    extractor::Extractors,
    model::{CurrentAdvisory, ExtractionLag},
    service::{freshness, tuning::WorkerConfig},
};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, FromQueryResult, Statement, TransactionTrait,
};
use time::OffsetDateTime;
use trustify_common::db;
use uuid::Uuid;

#[derive(FromQueryResult)]
struct Lag {
    pending_advisories: i64,
    failed: i64,
    oldest_pending_at: Option<OffsetDateTime>,
}

pub async fn lag(tx: &DatabaseTransaction) -> Result<ExtractionLag, Error> {
    let row = tx
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) pending_advisories, \
             count(*) FILTER (WHERE attempts > 0) failed, min(queued_at) oldest_pending_at \
             FROM correlation_extraction_queue",
        ))
        .await?
        .ok_or_else(|| sea_orm::DbErr::Custom("missing extraction lag".into()))?;
    let row = Lag::from_query_result(&row, "")?;
    let current =
        CurrentRow::find_by_statement(Statement::from_string(DbBackend::Postgres, CURRENT_SQL))
            .all(tx)
            .await?
            .into_iter()
            .map(|row| CurrentAdvisory {
                advisory_id: row.advisory_id,
                identifier: row.identifier,
                started_at: row.started_at,
            })
            .collect();
    Ok(ExtractionLag {
        pending_advisories: row.pending_advisories as u64,
        failed: row.failed as u64,
        oldest_pending_at: row.oldest_pending_at,
        current,
    })
}

#[derive(FromQueryResult)]
struct CurrentRow {
    advisory_id: Uuid,
    identifier: String,
    started_at: OffsetDateTime,
}

/// The advisories being extracted. An old row is left behind by a crashed worker, as an extraction
/// takes minutes at most.
const CURRENT_SQL: &str = "SELECT c.advisory_id, a.identifier, c.started_at \
    FROM correlation_extraction_current c JOIN advisory a ON a.id = c.advisory_id \
    WHERE c.started_at > now() - interval '1 hour' \
    ORDER BY c.started_at, c.advisory_id";

/// Publish what a worker is extracting, outside of its transaction. Failing to do so doesn't fail
/// the extraction.
async fn publish_current(db: &db::ReadWrite, statement: &str, advisory: Uuid) {
    let _ = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            statement,
            vec![advisory.into()],
        ))
        .await
        .inspect_err(|err| {
            tracing::warn!(%advisory, "failed to publish the extraction progress: {err}");
        });
}

/// Claim one event across all server instances. The queue row remains visible to
/// readers until evidence commits, and a crash rolls back the acknowledgement.
pub async fn run_step(
    db: &db::ReadWrite,
    extractors: &Extractors,
    config: &WorkerConfig,
) -> Result<bool, Error> {
    let tx = db.begin().await?;
    config.apply(&tx).await?;
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
    publish_current(
        db,
        "INSERT INTO correlation_extraction_current(advisory_id, started_at) \
         SELECT id, clock_timestamp() FROM advisory WHERE id = $1 \
         ON CONFLICT (advisory_id) DO UPDATE SET started_at = EXCLUDED.started_at",
        entity_id,
    )
    .await;
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
    let committed = tx.commit().await;
    publish_current(
        db,
        "DELETE FROM correlation_extraction_current WHERE advisory_id = $1",
        entity_id,
    )
    .await;
    committed?;
    Ok(true)
}

async fn extract(
    tx: &DatabaseTransaction,
    extractors: &Extractors,
    entity_type: &str,
    entity_id: Uuid,
) -> Result<(), Error> {
    if entity_type != "advisory" {
        return Err(Error::BadRequest("Unknown extraction entity type".into()));
    }
    // An advisory deleted before processing has no remaining extraction work.
    // Lock its parent while extracting, matching the evidence writers' lock order.
    if tx
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM advisory WHERE id = $1 FOR KEY SHARE",
            vec![entity_id.into()],
        ))
        .await?
        .is_none()
    {
        return Ok(());
    }
    extractors.extract_for_advisory(entity_id, tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
