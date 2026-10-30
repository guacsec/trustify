//! Indexed completion metadata, revision counters, and durable refresh jobs.
use crate::{error::Error, extractor::Extractors, model::*};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, FromQueryResult,
    JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait, TransactionTrait,
};
use std::collections::HashMap;
use time::OffsetDateTime;
use trustify_common::{
    db::{self, limiter::LimiterAsModelTrait, pagination_cache::PaginationCache, sql},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{correlation_extraction_state, sbom, sbom_node};
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
        .ok_or_else(|| DbErr::Custom("missing extraction revision".into()))?;
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

#[derive(FromQueryResult)]
struct DocumentCompletion {
    sbom_id: Uuid,
    name: String,
    completed_revision: i64,
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
                    return Err(DbErr::Custom(format!("unknown refresh status: {other}")).into());
                }
            },
            processed: self.processed as u64,
            failed: self.failed as u64,
            created_at: self.created_at,
            finished_at: self.finished_at,
        })
    }
}

/// Read the current extraction revision and document totals from maintained counters.
async fn load_counts(tx: &DatabaseTransaction) -> Result<Counts, Error> {
    let row = tx
        .query_one_raw(sql(OVERVIEW_COUNTS_SQL, vec![]))
        .await?
        .ok_or_else(|| DbErr::Custom("missing extraction counters".into()))?;
    Ok(Counts::from_query_result(&row, "")?)
}

pub async fn overview(tx: &DatabaseTransaction) -> Result<FreshnessOverview, Error> {
    let counts = load_counts(tx).await?;
    let mut result = FreshnessOverview {
        revision: counts.revision,
        checked_at: OffsetDateTime::now_utc(),
        total: counts.total as u64,
        current: counts.current as u64,
        stale: counts.stale as u64,
        unknown: counts.unknown as u64,
        needs_refresh: (counts.stale + counts.unknown) as u64,
        extraction_lag: Some(super::extraction::lag(tx).await?),
        verdict_lag: super::projection::lag(tx).await?,
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

/// Page SBOMs by extraction status using revision-ordered SQL selection.
/// Totals use maintained counters only when requested. Limits are validated against
/// the configured maximum; zero-limit requests skip document selection.
pub async fn documents(
    tx: &DatabaseTransaction,
    status: Option<FreshnessStatus>,
    page: Paginated,
    cache: &PaginationCache,
) -> Result<PaginatedResults<FreshnessDocument>, Error> {
    cache.check_limit(page.limit)?;
    if page.limit == 0 && !page.total {
        return Ok(PaginatedResults::default());
    }
    let (revision, total) = if page.total {
        let counts = load_counts(tx).await?;
        let total = match status {
            Some(FreshnessStatus::Current) => counts.current,
            Some(FreshnessStatus::Stale) => counts.stale,
            Some(FreshnessStatus::Unknown) => counts.unknown,
            None => counts.stale + counts.unknown,
        };
        (counts.revision, Some(total as u64))
    } else {
        let row = tx
            .query_one_raw(sql(
                "SELECT revision FROM correlation_extraction_revision",
                vec![],
            ))
            .await?
            .ok_or_else(|| DbErr::Custom("missing extraction revision".into()))?;
        (Revision::from_query_result(&row, "")?.revision, None)
    };
    if page.limit == 0 {
        return Ok(PaginatedResults {
            items: Vec::new(),
            total,
        });
    }
    let completed = correlation_extraction_state::Column::CompletedRevision;
    let mut query = correlation_extraction_state::Entity::find()
        .select_only()
        .column(correlation_extraction_state::Column::SbomId)
        .column(completed)
        .column(correlation_extraction_state::Column::CompletedAt)
        .column_as(sbom_node::Column::Name, "name")
        .join(
            JoinType::InnerJoin,
            correlation_extraction_state::Relation::Sbom.def(),
        )
        .join(JoinType::InnerJoin, sbom::Relation::SbomNode.def());
    query = match status {
        Some(FreshnessStatus::Current) => query.filter(completed.eq(revision)),
        Some(FreshnessStatus::Stale) => query
            .filter(completed.gt(0_i64))
            .filter(completed.lt(revision)),
        Some(FreshnessStatus::Unknown) => query.filter(completed.eq(0_i64)),
        None => query.filter(completed.lt(revision)),
    };
    let selected = query
        .order_by_asc(completed)
        .order_by_asc(correlation_extraction_state::Column::SbomId)
        .limiting_as::<DocumentCompletion>(tx, page, cache)?
        .fetch()
        .await?;
    let items = selected
        .items
        .into_iter()
        .map(|row| FreshnessDocument {
            sbom_id: row.sbom_id,
            name: row.name,
            freshness: completion(&Completion {
                sbom_id: row.sbom_id,
                revision,
                completed_revision: Some(row.completed_revision),
                completed_at: row.completed_at,
            }),
        })
        .collect();
    Ok(PaginatedResults { items, total })
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
        .ok_or_else(|| DbErr::Custom("failed to create refresh job".into()))?;
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
    let Some(row) = tx.query_one_raw(sql("SELECT * FROM correlation_refresh_job WHERE status IN ('queued','running') FOR UPDATE SKIP LOCKED", vec![])).await? else {
        // Settings changes schedule their refresh automatically. Failed sweeps wait before retry.
        let needed = tx.query_one_raw(sql("SELECT 1 FROM correlation_extraction_state WHERE completed_revision > 0 AND completed_revision < $1 AND NOT EXISTS (SELECT 1 FROM correlation_refresh_job WHERE status IN ('queued','running') OR (failed > 0 AND finished_at > now()-interval '30 seconds')) LIMIT 1", vec![revision.into()])).await?.is_some();
        if needed { start(&tx).await?; tx.commit().await?; }
        return Ok(needed);
    };
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
