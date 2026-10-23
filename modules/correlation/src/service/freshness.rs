//! Indexed completion metadata, revision counters, and durable refresh jobs.
use crate::{error::Error, extractor::Extractors, model::*};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, FromQueryResult, Statement, TransactionTrait,
};
use std::collections::HashMap;
use time::OffsetDateTime;
use trustify_common::{
    db,
    model::{Paginated, PaginatedResults},
};
use uuid::Uuid;

#[cfg(test)]
mod tests;

const OVERVIEW_COUNTS_SQL: &str = r#"
SELECT r.revision,
       COALESCE(sum(c.documents),0)::bigint total,
       COALESCE(sum(c.documents) FILTER (WHERE c.revision = r.revision),0)::bigint current,
       COALESCE(sum(c.documents) FILTER (WHERE c.revision > 0 AND c.revision <> r.revision),0)::bigint stale,
       COALESCE(sum(c.documents) FILTER (WHERE c.revision = 0),0)::bigint unknown
FROM correlation_extraction_revision r
LEFT JOIN correlation_extraction_count c ON true
GROUP BY r.revision
"#;

const NEXT_DOCUMENT_SQL: &str = r#"
SELECT sbom_id, completed_revision FROM correlation_extraction_state
WHERE completed_revision < $1
  AND ($2::uuid IS NULL OR (completed_revision, sbom_id) > ($3, $2))
ORDER BY completed_revision, sbom_id LIMIT 1
"#;

fn sql(query: &str, values: Vec<sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, query, values)
}

#[derive(FromQueryResult)]
struct Revision {
    revision: i64,
}

/// Shared for the entire matching transaction; option invalidation takes the exclusive lock.
pub async fn lock_revision(tx: &DatabaseTransaction) -> Result<i64, Error> {
    let row = tx
        .query_one_raw(sql(
            "SELECT revision FROM correlation_extraction_revision FOR SHARE",
            vec![],
        ))
        .await?
        .ok_or_else(|| sea_orm::DbErr::Custom("missing extraction revision".into()))?;
    Ok(Revision::from_query_result(&row, "")?.revision)
}

/// Every ingestion and refresh writer locks the same document metadata in UUID order.
pub async fn lock_sboms(tx: &DatabaseTransaction, ids: Vec<Uuid>) -> Result<(), Error> {
    // Lock parents first, matching cascading deletion's order. Otherwise a deletion
    // could hold the parent while waiting for metadata and deadlock an evidence FK insert.
    tx.query_all_raw(sql(
        "SELECT sbom_id FROM sbom WHERE sbom_id = ANY($1) ORDER BY sbom_id FOR KEY SHARE",
        vec![ids.clone().into()],
    ))
    .await?;
    tx.query_all_raw(sql("SELECT sbom_id FROM correlation_extraction_state WHERE sbom_id = ANY($1) ORDER BY sbom_id FOR UPDATE", vec![ids.into()])).await?;
    Ok(())
}

#[derive(FromQueryResult)]
struct Completion {
    sbom_id: Uuid,
    revision: i64,
    completed_revision: Option<i64>,
    completed_at: Option<OffsetDateTime>,
}

fn completion(row: &Completion) -> ExtractionFreshness {
    let completed = row.completed_revision.filter(|r| *r > 0);
    ExtractionFreshness {
        status: match completed {
            None => FreshnessStatus::Unknown,
            Some(r) if r == row.revision => FreshnessStatus::Current,
            Some(_) => FreshnessStatus::Stale,
        },
        required_revision: row.revision,
        completed_revision: completed,
        completed_at: row.completed_at,
    }
}

pub async fn for_sboms(
    tx: &DatabaseTransaction,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, ExtractionFreshness>, Error> {
    let mut result = HashMap::new();
    for ids in ids.chunks(1000) {
        for row in tx.query_all_raw(sql(
            "SELECT ids.sbom_id, r.revision, s.completed_revision, s.completed_at FROM unnest($1::uuid[]) ids(sbom_id) CROSS JOIN correlation_extraction_revision r LEFT JOIN correlation_extraction_state s USING (sbom_id)",
            vec![ids.to_vec().into()],
        )).await? {
            let row = Completion::from_query_result(&row, "")?;
            result.insert(row.sbom_id, completion(&row));
        }
    }
    Ok(result)
}

/// Full replacement, including an empty result. Caller commits evidence and completion together.
pub async fn refresh_sbom(
    extractors: &Extractors,
    id: Uuid,
    tx: &DatabaseTransaction,
) -> Result<(), Error> {
    let revision = lock_revision(tx).await?;
    lock_sboms(tx, vec![id]).await?;
    tx.execute_raw(sql(
        "DELETE FROM correlation_evidence WHERE sbom_id = $1",
        vec![id.into()],
    ))
    .await?;
    extractors.extract_for_sbom(id, tx).await?;
    tx.execute_raw(sql("UPDATE correlation_extraction_state SET completed_revision = $2, completed_at = clock_timestamp() WHERE sbom_id = $1", vec![id.into(), revision.into()])).await?;
    Ok(())
}

#[derive(FromQueryResult)]
struct Counts {
    revision: i64,
    total: i64,
    current: i64,
    stale: i64,
    unknown: i64,
}

#[derive(FromQueryResult)]
struct JobRow {
    id: Uuid,
    revision: i64,
    status: String,
    cursor: Option<Uuid>,
    cursor_revision: Option<i64>,
    processed: i64,
    failed: i64,
    created_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
}

impl JobRow {
    fn model(&self) -> Result<RefreshJob, Error> {
        Ok(RefreshJob {
            id: self.id,
            revision: self.revision,
            status: match self.status.as_str() {
                "queued" => RefreshJobStatus::Queued,
                "running" => RefreshJobStatus::Running,
                "completed" => RefreshJobStatus::Completed,
                "superseded" => RefreshJobStatus::Superseded,
                other => {
                    return Err(
                        sea_orm::DbErr::Custom(format!("unknown refresh status: {other}")).into(),
                    );
                }
            },
            processed: self.processed as u64,
            failed: self.failed as u64,
            created_at: self.created_at,
            finished_at: self.finished_at,
        })
    }
}

pub async fn overview(tx: &DatabaseTransaction) -> Result<FreshnessOverview, Error> {
    let row = tx
        .query_one_raw(sql(OVERVIEW_COUNTS_SQL, vec![]))
        .await?
        .ok_or_else(|| sea_orm::DbErr::Custom("missing extraction counters".into()))?;
    let counts = Counts::from_query_result(&row, "")?;
    let mut result = FreshnessOverview {
        revision: counts.revision,
        checked_at: OffsetDateTime::now_utc(),
        total: counts.total as u64,
        current: counts.current as u64,
        stale: counts.stale as u64,
        unknown: counts.unknown as u64,
        needs_refresh: (counts.stale + counts.unknown) as u64,
        extraction_lag: Some(super::extraction::lag(tx).await?),
        active_job: None,
        latest_job: None,
    };
    if let Some(row) = tx
        .query_one_raw(sql(
            "SELECT * FROM correlation_refresh_job ORDER BY created_at DESC, id DESC LIMIT 1",
            vec![],
        ))
        .await?
    {
        let job = JobRow::from_query_result(&row, "")?.model()?;
        if matches!(
            job.status,
            RefreshJobStatus::Queued | RefreshJobStatus::Running
        ) {
            result.active_job = Some(job.clone());
        }
        result.latest_job = Some(job);
    }
    Ok(result)
}

pub async fn documents(
    tx: &DatabaseTransaction,
    status: Option<FreshnessStatus>,
    page: Paginated,
) -> Result<PaginatedResults<FreshnessDocument>, Error> {
    // Each branch has an indexable revision predicate. None means the refresh backlog.
    let revision = overview(tx).await?;
    let predicate = match status {
        Some(FreshnessStatus::Current) => "s.completed_revision = $1",
        Some(FreshnessStatus::Stale) => "s.completed_revision > 0 AND s.completed_revision < $1",
        Some(FreshnessStatus::Unknown) => "s.completed_revision = 0",
        None => "s.completed_revision < $1",
    };
    // Unknown still binds $1 in the projection, keeping one stable parameter layout.
    let query = format!(
        "SELECT s.sbom_id, n.name, $1::bigint revision, s.completed_revision, s.completed_at FROM correlation_extraction_state s JOIN sbom b USING (sbom_id) JOIN sbom_node n ON n.sbom_id = b.sbom_id AND n.node_id = b.node_id WHERE {predicate} ORDER BY s.completed_revision, s.sbom_id LIMIT $2 OFFSET $3"
    );
    let mut items = Vec::new();
    for row in tx
        .query_all_raw(sql(
            &query,
            vec![
                revision.revision.into(),
                (page.limit.min(1000) as i64).into(),
                (page.offset.min(i64::MAX as u64) as i64).into(),
            ],
        ))
        .await?
    {
        let state = Completion::from_query_result(&row, "")?;
        items.push(FreshnessDocument {
            sbom_id: state.sbom_id,
            name: row.try_get("", "name")?,
            freshness: completion(&state),
        });
    }
    let count = match status {
        Some(FreshnessStatus::Current) => revision.current,
        Some(FreshnessStatus::Stale) => revision.stale,
        Some(FreshnessStatus::Unknown) => revision.unknown,
        None => revision.needs_refresh,
    };
    Ok(PaginatedResults {
        items,
        total: page.total.then_some(count),
    })
}

pub async fn start(tx: &DatabaseTransaction) -> Result<RefreshJob, Error> {
    // Serialize requests without blocking extraction's shared revision lock.
    tx.execute_raw(sql("SELECT pg_advisory_xact_lock(2680, 1)", vec![]))
        .await?;
    let revision = lock_revision(tx).await?;
    if let Some(row) = tx
        .query_one_raw(sql(
            "SELECT * FROM correlation_refresh_job WHERE status IN ('queued','running')",
            vec![],
        ))
        .await?
    {
        return JobRow::from_query_result(&row, "")?.model();
    }
    let row = tx.query_one_raw(sql("INSERT INTO correlation_refresh_job(id, revision, status) VALUES ($1,$2,'queued') RETURNING *", vec![Uuid::now_v7().into(), revision.into()])).await?
        .ok_or_else(|| sea_orm::DbErr::Custom("failed to create refresh job".into()))?;
    JobRow::from_query_result(&row, "")?.model()
}

pub async fn job(
    tx: &DatabaseTransaction,
    id: Uuid,
    page: Paginated,
) -> Result<RefreshJobDetails, Error> {
    let row = tx
        .query_one_raw(sql(
            "SELECT * FROM correlation_refresh_job WHERE id = $1",
            vec![id.into()],
        ))
        .await?
        .ok_or_else(|| Error::NotFound(id.to_string()))?;
    let job = JobRow::from_query_result(&row, "")?.model()?;
    let mut failures = Vec::new();
    for row in tx.query_all_raw(sql("SELECT sbom_id, error FROM correlation_refresh_outcome WHERE job_id = $1 AND error IS NOT NULL ORDER BY sbom_id LIMIT $2 OFFSET $3", vec![id.into(), (page.limit.min(1000) as i64).into(), (page.offset.min(i64::MAX as u64) as i64).into()])).await? {
        failures.push(RefreshFailure { sbom_id: row.try_get("", "sbom_id")?, error: row.try_get("", "error")? });
    }
    Ok(RefreshJobDetails {
        failure_total: job.failed,
        job,
        failures,
    })
}

/// Process one document while holding the durable job row. A crash rolls back both
/// evidence and the cursor, so any instance can resume it without a lease timeout.
pub async fn run_step(db: &db::ReadWrite, extractors: &Extractors) -> Result<bool, Error> {
    let tx = db.begin().await?;
    let revision = lock_revision(&tx).await?;
    let Some(row) = tx.query_one_raw(sql("SELECT * FROM correlation_refresh_job WHERE status IN ('queued','running') FOR UPDATE SKIP LOCKED", vec![])).await? else { return Ok(false); };
    let job = JobRow::from_query_result(&row, "")?;
    if job.revision != revision {
        tx.execute_raw(sql("UPDATE correlation_refresh_job SET status = 'superseded', finished_at = clock_timestamp() WHERE id = $1", vec![job.id.into()])).await?;
        tx.commit().await?;
        return Ok(false);
    }
    let row = tx
        .query_one_raw(sql(
            NEXT_DOCUMENT_SQL,
            vec![
                revision.into(),
                job.cursor.into(),
                job.cursor_revision.into(),
            ],
        ))
        .await?;
    let Some(row) = row else {
        tx.execute_raw(sql("UPDATE correlation_refresh_job SET status = 'completed', finished_at = clock_timestamp() WHERE id = $1", vec![job.id.into()])).await?;
        tx.commit().await?;
        return Ok(false);
    };
    let id: Uuid = row.try_get("", "sbom_id")?;
    let cursor_revision: i64 = row.try_get("", "completed_revision")?;
    tx.execute_raw(sql(
        "UPDATE correlation_refresh_job SET status = 'running' WHERE id = $1",
        vec![job.id.into()],
    ))
    .await?;
    // A savepoint preserves the job lock while rolling back a failed extraction.
    let work = tx.begin().await?;
    let error = match refresh_sbom(extractors, id, &work).await {
        Ok(()) => {
            work.commit().await?;
            None
        }
        Err(err) => {
            tracing::warn!(sbom_id = %id, job_id = %job.id, error = %err, "correlation refresh failed");
            work.rollback().await?;
            // Keep internal database details in the server log, not the public API.
            Some("Extraction failed; see server logs and retry the refresh".to_string())
        }
    };
    tx.execute_raw(sql(
        "INSERT INTO correlation_refresh_outcome(job_id,sbom_id,error) VALUES ($1,$2,$3)",
        vec![job.id.into(), id.into(), error.clone().into()],
    ))
    .await?;
    tx.execute_raw(sql("UPDATE correlation_refresh_job SET cursor = $2, processed = processed + $3, failed = failed + $4, cursor_revision = $5 WHERE id = $1", vec![job.id.into(), id.into(), i64::from(error.is_none()).into(), i64::from(error.is_some()).into(), cursor_revision.into()])).await?;
    tx.commit().await?;
    Ok(true)
}
