//! Indexed completion metadata, revision counters, and durable refresh jobs.
//!
//! Never-extracted SBOMs and SBOMs outdated by a settings change are handled alike:
//! whenever any document is behind the current revision, the worker schedules a job.
use crate::{
    error::Error,
    extractor::{ExtractionProgress, Extractors},
    model::*,
    service::tuning::WorkerConfig,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, FromQueryResult,
    JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait, TransactionTrait,
};
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use tracing::instrument;
use trustify_common::{
    db::{self, limiter::LimiterAsModelTrait, pagination_cache::PaginationCache, sql},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{correlation_extraction_state, sbom, sbom_node, sbom_package};
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

/// The next documents behind the revision which this job has not attempted yet, including the
/// ones other workers are extracting. Successful documents become current and leave the set;
/// failed ones are skipped by their outcome. Never-extracted documents sort first, so new SBOMs
/// are picked up during a long refresh.
///
/// A worker claims the first one no other worker holds, so this must return more documents than
/// there are workers.
const NEXT_DOCUMENTS_SQL: &str = r#"
SELECT sbom_id FROM correlation_extraction_state s
WHERE completed_revision < $1
  AND NOT EXISTS (
    SELECT 1 FROM correlation_refresh_outcome o WHERE o.job_id = $2 AND o.sbom_id = s.sbom_id
  )
ORDER BY completed_revision, sbom_id LIMIT 256
"#;

/// Whether a document still needs to be extracted by a job, after claiming it: another worker may
/// have finished it since it was selected.
const OUTSTANDING_SQL: &str = r#"
SELECT 1 FROM correlation_extraction_state s
WHERE sbom_id = $3 AND completed_revision < $1
  AND NOT EXISTS (
    SELECT 1 FROM correlation_refresh_outcome o WHERE o.job_id = $2 AND o.sbom_id = s.sbom_id
  )
"#;

/// Schedule a job when a document is behind the revision. After a job with failures,
/// wait before retrying them, so persistently failing documents do not spin the worker.
const NEEDS_JOB_SQL: &str = r#"
SELECT 1 FROM correlation_extraction_state
WHERE completed_revision < $1
  AND NOT EXISTS (
    SELECT 1 FROM correlation_refresh_job
    WHERE status IN ('queued','running')
       OR (failed > 0 AND finished_at > now() - interval '30 seconds')
  )
LIMIT 1
"#;

/// The documents a job is extracting, published outside the workers' own transactions.
///
/// Only while a worker holds the document's claim (see [`claim`]): a stopped worker leaves its row
/// behind, until another worker claims the document again.
const CURRENT_SQL: &str = r#"
SELECT c.sbom_id, n.name, c.started_at, c.done, c.total FROM correlation_refresh_current c
JOIN sbom s USING (sbom_id)
LEFT JOIN sbom_node n ON n.sbom_id = s.sbom_id AND n.node_id = s.node_id
WHERE c.job_id = $1
  AND EXISTS (
    SELECT 1 FROM pg_locks l
    WHERE l.locktype = 'advisory' AND l.granted AND l.database = (
        SELECT oid FROM pg_database WHERE datname = current_database()
      )
      -- the two keys of pg_try_advisory_xact_lock(2681, hashtext(..))
      AND l.classid = 2681 AND l.objid = hashtext(c.sbom_id::text)::oid AND l.objsubid = 2
  )
ORDER BY c.started_at, c.sbom_id
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
            [],
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
    progress: &dyn ExtractionProgress,
    tx: &DatabaseTransaction,
) -> Result<(), Error> {
    let revision = lock_revision(tx).await?;
    lock_sboms(tx, vec![id]).await?;
    tx.execute_raw(sql(
        "DELETE FROM correlation_evidence WHERE sbom_id = $1",
        vec![id.into()],
    ))
    .await?;
    extractors
        .extract_for_sbom_reporting(id, progress, tx)
        .await?;
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
    processed: i64,
    failed: i64,
    created_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
}

impl JobRow {
    /// Convert into the API model. `pending` is the number of documents behind the
    /// current revision, used to estimate the remaining work of an active job, and
    /// `current` the documents it is extracting.
    fn model(
        &self,
        pending: u64,
        now: OffsetDateTime,
        current: Vec<CurrentSbom>,
    ) -> Result<RefreshJob, Error> {
        let mut job = RefreshJob {
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
            remaining: 0,
            estimated_completion_at: None,
            created_at: self.created_at,
            finished_at: self.finished_at,
            current: Vec::new(),
        };
        if matches!(
            job.status,
            RefreshJobStatus::Queued | RefreshJobStatus::Running
        ) {
            (job.remaining, job.estimated_completion_at) = estimate(&job, pending, now);
            if !current.is_empty() {
                // The status change commits with the first document; the current
                // documents are published right away.
                job.status = RefreshJobStatus::Running;
                job.current = current;
            }
        }
        Ok(job)
    }

    /// Convert into the API model, loading the documents an active job is extracting.
    async fn load(
        &self,
        tx: &DatabaseTransaction,
        pending: u64,
        now: OffsetDateTime,
    ) -> Result<RefreshJob, Error> {
        let current = RefreshCurrentRow::find_by_statement(sql(CURRENT_SQL, vec![self.id.into()]))
            .all(tx)
            .await?
            .into_iter()
            .map(|row| {
                let progress = match row.total {
                    0 => None,
                    total => Some(WorkProgress {
                        done: u64::try_from(row.done)?,
                        total: u64::try_from(total)?,
                    }),
                };
                Ok(CurrentSbom {
                    progress,
                    ..row.sbom.into()
                })
            })
            .collect::<Result<_, Error>>()?;
        self.model(pending, now, current)
    }
}

/// A document a refresh job is extracting, with the chunks extracted so far.
#[derive(FromQueryResult)]
struct RefreshCurrentRow {
    #[sea_orm(nested)]
    sbom: CurrentRow,
    done: i64,
    total: i64,
}

#[derive(FromQueryResult)]
pub(super) struct CurrentRow {
    sbom_id: Uuid,
    name: Option<String>,
    started_at: OffsetDateTime,
}

impl From<CurrentRow> for CurrentSbom {
    fn from(row: CurrentRow) -> Self {
        Self {
            sbom_id: row.sbom_id,
            name: row.name,
            started_at: row.started_at,
            progress: None,
        }
    }
}

/// Estimate the remaining documents and completion time of an active job.
///
/// Documents which failed in this job stay behind the revision but are not retried by it.
/// The rate is the job's average so far, so there is no estimate before the first document.
fn estimate(job: &RefreshJob, pending: u64, now: OffsetDateTime) -> (u64, Option<OffsetDateTime>) {
    let remaining = pending.saturating_sub(job.failed);
    let done = job.processed + job.failed;
    let elapsed = now - job.created_at;
    if done == 0 || !elapsed.is_positive() {
        return (remaining, None);
    }
    let eta =
        Duration::checked_seconds_f64(elapsed.as_seconds_f64() * remaining as f64 / done as f64)
            .and_then(|left| now.checked_add(left));
    (remaining, eta)
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
    let now = OffsetDateTime::now_utc();
    let pending = (counts.stale + counts.unknown) as u64;
    let mut result = FreshnessOverview {
        revision: counts.revision,
        checked_at: now,
        total: counts.total as u64,
        current: counts.current as u64,
        stale: counts.stale as u64,
        unknown: counts.unknown as u64,
        needs_refresh: pending,
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
        let job = JobRow::from_query_result(&row, "")?
            .load(tx, pending, now)
            .await?;
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
    let packages = package_counts(selected.items.iter().map(|row| row.sbom_id), tx).await?;
    let items = selected
        .items
        .into_iter()
        .map(|row| FreshnessDocument {
            sbom_id: row.sbom_id,
            name: row.name,
            packages: packages.get(&row.sbom_id).copied().unwrap_or_default(),
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

/// The number of packages of each of the given SBOMs. SBOMs without packages are omitted.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
async fn package_counts(
    sbom_ids: impl IntoIterator<Item = Uuid>,
    tx: &DatabaseTransaction,
) -> Result<HashMap<Uuid, u64>, Error> {
    let sbom_ids = sbom_ids.into_iter().collect::<Vec<_>>();
    if sbom_ids.is_empty() {
        return Ok(HashMap::new());
    }
    sbom_package::Entity::find()
        .select_only()
        .column(sbom_package::Column::SbomId)
        .column_as(sbom_package::Column::NodeId.count(), "packages")
        .filter(sbom_package::Column::SbomId.is_in(sbom_ids))
        .group_by(sbom_package::Column::SbomId)
        .into_tuple::<(Uuid, i64)>()
        .all(tx)
        .await?
        .into_iter()
        .map(|(sbom_id, packages)| Ok((sbom_id, u64::try_from(packages)?)))
        .collect()
}

/// Schedule a refresh job, or return the active one. Called by the worker only.
async fn start(tx: &DatabaseTransaction) -> Result<RefreshJob, Error> {
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
        return JobRow::from_query_result(&row, "")?.model(
            0,
            OffsetDateTime::now_utc(),
            Vec::new(),
        );
    }
    let row = tx.query_one_raw(sql("INSERT INTO correlation_refresh_job(id, revision, status) VALUES ($1,$2,'queued') RETURNING *", vec![Uuid::now_v7().into(), revision.into()])).await?
        .ok_or_else(|| DbErr::Custom("failed to create refresh job".into()))?;
    JobRow::from_query_result(&row, "")?.model(0, OffsetDateTime::now_utc(), Vec::new())
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
    let counts = load_counts(tx).await?;
    let job = JobRow::from_query_result(&row, "")?
        .load(
            tx,
            (counts.stale + counts.unknown) as u64,
            OffsetDateTime::now_utc(),
        )
        .await?;
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

/// Process one document of the active job, scheduling a job first when documents are behind
/// the revision.
///
/// Workers of all instances share the job, each extracting a document it claims with a lock
/// held until it commits (see [`claim`]). A crash rolls back both evidence and the outcome, so any
/// instance can resume the document without a lease timeout. The job row itself is only updated
/// briefly, with each document's outcome, and when the job finishes: it completes when no
/// document is left, including the ones in flight, and is superseded only by a new revision,
/// which waits for all documents in flight (see [`lock_revision`]).
pub async fn run_step(
    db: &db::ReadWrite,
    extractors: &Extractors,
    config: &WorkerConfig,
) -> Result<bool, Error> {
    let tx = db.begin().await?;
    config.apply(&tx).await?;
    let revision = lock_revision(&tx).await?;
    let Some(row) = tx
        .query_one_raw(sql(
            "SELECT * FROM correlation_refresh_job WHERE status IN ('queued','running')",
            vec![],
        ))
        .await?
    else {
        let needed = tx
            .query_one_raw(sql(NEEDS_JOB_SQL, vec![revision.into()]))
            .await?
            .is_some();
        if needed {
            start(&tx).await?;
            tx.commit().await?;
        }
        return Ok(needed);
    };
    let job = JobRow::from_query_result(&row, "")?;
    if job.revision != revision {
        finish(&tx, job.id, Finish::Superseded).await?;
        // replace it right away, so documents behind the revision always have a job
        let needed = tx
            .query_one_raw(sql(NEEDS_JOB_SQL, vec![revision.into()]))
            .await?
            .is_some();
        if needed {
            start(&tx).await?;
        }
        tx.commit().await?;
        return Ok(true);
    }
    let id = match claim(&tx, revision, job.id).await? {
        Claim::Document(id) => id,
        Claim::InFlight => return Ok(false),
        Claim::Done => {
            finish(&tx, job.id, Finish::Completed).await?;
            tx.commit().await?;
            return Ok(false);
        }
    };
    // Make the document visible while it is extracted; this transaction commits after.
    db.execute_raw(sql(
        "INSERT INTO correlation_refresh_current(job_id, sbom_id, started_at) VALUES ($1, $2, clock_timestamp()) ON CONFLICT (job_id, sbom_id) DO UPDATE SET started_at = EXCLUDED.started_at, done = 0, total = 0",
        vec![job.id.into(), id.into()],
    ))
    .await?;
    // A savepoint preserves the claim while rolling back a failed extraction.
    let work = tx.begin().await?;
    let progress = RefreshProgress {
        db,
        job_id: job.id,
        sbom_id: id,
    };
    let error = match refresh_sbom(extractors, id, &progress, &work).await {
        Ok(()) => {
            work.commit().await?;
            None
        }
        Err(err) => {
            tracing::warn!(sbom_id = %id, job_id = %job.id, error = %err, "correlation refresh failed");
            work.rollback().await?;
            // Keep internal database details in the server log, not the public API.
            Some("Extraction failed and is retried automatically; see server logs".to_string())
        }
    };
    tx.execute_raw(sql(
        "INSERT INTO correlation_refresh_outcome(job_id,sbom_id,error) VALUES ($1,$2,$3)",
        vec![job.id.into(), id.into(), error.clone().into()],
    ))
    .await?;
    tx.execute_raw(sql(
        "DELETE FROM correlation_refresh_current WHERE job_id = $1 AND sbom_id = $2",
        vec![job.id.into(), id.into()],
    ))
    .await?;
    // last, as concurrent workers wait for each other's update of the job row until they commit
    tx.execute_raw(sql("UPDATE correlation_refresh_job SET status = 'running', processed = processed + $2, failed = failed + $3 WHERE id = $1", vec![job.id.into(), i64::from(error.is_none()).into(), i64::from(error.is_some()).into()])).await?;
    tx.commit().await?;
    Ok(true)
}

/// Publishes the chunks of a job's document extracted so far, outside of the worker's transaction.
/// Failing to do so doesn't fail the extraction.
struct RefreshProgress<'a> {
    db: &'a db::ReadWrite,
    job_id: Uuid,
    sbom_id: Uuid,
}

#[async_trait::async_trait]
impl ExtractionProgress for RefreshProgress<'_> {
    async fn chunks_done(&self, done: usize, total: usize) {
        // a single chunk tells nothing, and the row is removed once all chunks are done
        if total <= 1 || done >= total {
            return;
        }
        let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
        let _ = self
            .db
            .execute_raw(sql(
                "UPDATE correlation_refresh_current SET done = $3, total = $4 WHERE job_id = $1 AND sbom_id = $2",
                vec![
                    self.job_id.into(),
                    self.sbom_id.into(),
                    count(done).into(),
                    count(total).into(),
                ],
            ))
            .await
            .inspect_err(|err| {
                tracing::warn!(sbom_id = %self.sbom_id, "failed to publish the extraction progress: {err}");
            });
    }
}

/// The outcome of claiming a document of a job.
enum Claim {
    /// The document this worker extracts.
    Document(Uuid),
    /// All outstanding documents are being extracted by other workers.
    InFlight,
    /// No document is left.
    Done,
}

/// Claim the next outstanding document of a job.
///
/// The claim is a transaction scoped advisory lock: unlike a row lock, it can't take part in a
/// deadlock with the locks of extracting and deleting an SBOM (see [`lock_sboms`]).
async fn claim(tx: &DatabaseTransaction, revision: i64, job: Uuid) -> Result<Claim, Error> {
    let candidates = tx
        .query_all_raw(sql(NEXT_DOCUMENTS_SQL, vec![revision.into(), job.into()]))
        .await?;
    if candidates.is_empty() {
        return Ok(Claim::Done);
    }
    for row in candidates {
        let id: Uuid = row.try_get("", "sbom_id")?;
        let locked = tx
            .query_one_raw(sql(
                "SELECT pg_try_advisory_xact_lock(2681, hashtext($1::text)) AS locked",
                vec![id.into()],
            ))
            .await?
            .map(|row| row.try_get::<bool>("", "locked"))
            .transpose()?
            .unwrap_or(false);
        if locked
            && tx
                .query_one_raw(sql(
                    OUTSTANDING_SQL,
                    vec![revision.into(), job.into(), id.into()],
                ))
                .await?
                .is_some()
        {
            return Ok(Claim::Document(id));
        }
    }
    Ok(Claim::InFlight)
}

/// How a job finished.
#[derive(Clone, Copy)]
enum Finish {
    /// All documents were processed.
    Completed,
    /// The revision changed.
    Superseded,
}

impl Finish {
    /// The status stored in `correlation_refresh_job`.
    fn status(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Superseded => "superseded",
        }
    }
}

/// Finish an active job, removing its published documents.
async fn finish(tx: &DatabaseTransaction, job: Uuid, finish: Finish) -> Result<(), Error> {
    tx.execute_raw(sql(
        "UPDATE correlation_refresh_job SET status = $2, finished_at = clock_timestamp() \
         WHERE id = $1 AND status IN ('queued','running')",
        vec![job.into(), finish.status().into()],
    ))
    .await?;
    tx.execute_raw(sql(
        "DELETE FROM correlation_refresh_current WHERE job_id = $1",
        vec![job.into()],
    ))
    .await?;
    Ok(())
}
