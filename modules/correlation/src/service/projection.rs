//! Durable default verdict snapshots. Reads never run the resolver.
use super::{
    CorrelationService, class, freshness,
    pagination::{self, EvidenceGroup},
    resolution::ProviderSnapshot,
    tuning::WorkerConfig,
};
use crate::{
    error::Error,
    model::{
        CurrentSbom, ResolutionRequest, SbomVerdictCounts, SbomVerdictPage, VerdictFreshness,
        VerdictLag, VerdictStatus, VerdictSummary, WorkProgress,
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, ExprTrait,
    FromQueryResult, JoinType, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
    sea_query::Expr,
};
use std::collections::{HashMap, HashSet};
use tracing::{Instrument, info_span};
use trustify_common::{
    db::{self, limiter::LimiterAsModelTrait, pagination_cache::PaginationCache, sql},
    model::Pagination,
};
use trustify_entity::{correlation_node_class, correlation_verdict, correlation_verdict_freshness};
use uuid::Uuid;

/// Bump in a migration together with changes to the default resolver's semantics.
const RESOLVER_VERSION: i32 = 1;
const BATCH_SIZE: usize = 1000;

/// Read completion and upstream freshness in a single database snapshot.
pub async fn state(
    ids: &[Uuid],
    tx: &impl ConnectionTrait,
) -> Result<HashMap<Uuid, VerdictFreshness>, Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(correlation_verdict_freshness::Entity::find()
        .filter(correlation_verdict_freshness::Column::SbomId.is_in(ids.iter().copied()))
        .all(tx)
        .await?
        .into_iter()
        .map(|row| (row.sbom_id, row.into()))
        .collect())
}

impl CorrelationService {
    /// Page published verdicts. Counts are optional and cached by generation and filters.
    pub async fn verdict_page(
        &self,
        sbom_id: Uuid,
        request: &ResolutionRequest,
        paginated: impl Pagination,
        cache: &PaginationCache,
        tx: &DatabaseTransaction,
    ) -> Result<SbomVerdictPage, Error> {
        self.filtered_verdict_page(sbom_id, request, None, paginated, cache, tx)
            .await
    }

    /// Select published verdicts by node, vulnerability, and resolved status before paging.
    #[allow(clippy::too_many_arguments)]
    pub async fn filtered_verdict_page(
        &self,
        sbom_id: Uuid,
        request: &ResolutionRequest,
        status: Option<VerdictStatus>,
        paginated: impl Pagination,
        cache: &PaginationCache,
        tx: &DatabaseTransaction,
    ) -> Result<SbomVerdictPage, Error> {
        cache.check_limit(paginated.limit())?;
        let freshness = state(&[sbom_id], tx)
            .await?
            .remove(&sbom_id)
            .unwrap_or_default();
        // a verdict of a representative is one for each member of its class
        let member = Expr::cust(MEMBER);
        let mut query = correlation_verdict::Entity::find()
            .join(
                JoinType::LeftJoin,
                correlation_verdict::Entity::belongs_to(correlation_node_class::Entity)
                    .from((
                        correlation_verdict::Column::SbomId,
                        correlation_verdict::Column::NodeId,
                    ))
                    .to((
                        correlation_node_class::Column::SbomId,
                        correlation_node_class::Column::RepresentativeNodeId,
                    ))
                    .into(),
            )
            .column_as(member.clone(), "member_node_id")
            .filter(correlation_verdict::Column::SbomId.eq(sbom_id));
        if let Some(node) = &request.node_id {
            query = query.filter(member.clone().eq(node));
        }
        if let Some(vuln) = &request.vulnerability_id {
            query = query.filter(correlation_verdict::Column::VulnerabilityId.eq(vuln));
        }
        if let Some(status) = status {
            query = query.filter(
                correlation_verdict::Column::Status
                    .eq(correlation_verdict::VerdictStatus::from(status)),
            );
        }
        // Include the generation in the shared limiter's bound-value cache key.
        let generation = freshness.generation.unwrap_or_default();
        query = query.filter(Expr::val(generation).eq(generation));
        let selected = query
            .order_by_asc(member)
            .order_by_asc(correlation_verdict::Column::VulnerabilityId)
            .limiting_as::<VerdictRow>(tx, paginated, cache)?
            .fetch()
            .await?;
        let total = selected.total.requested(paginated.total()).await?;
        let members = selected
            .items
            .iter()
            .filter(|row| row.member_node_id != row.node_id)
            .map(|row| row.member_node_id.clone())
            .collect::<Vec<_>>();
        let names = class::names(sbom_id, members, tx).await?;
        let items = selected
            .items
            .into_iter()
            .map(|row| {
                let mut verdict: VerdictSummary =
                    serde_json::from_value(row.snapshot).map_err(Error::MatchedValue)?;
                if !request.include_explanation {
                    verdict.resolution.explanation = None;
                }
                Ok(class::for_member(verdict, &row.member_node_id, &names))
            })
            .collect::<Result<_, Error>>()?;
        Ok(SbomVerdictPage {
            items,
            total,
            freshness,
        })
    }
}

/// The member node of a verdict row, see [`class`].
const MEMBER: &str = "coalesce(correlation_node_class.node_id, correlation_verdict.node_id)";

/// A published verdict, for one member of the class of its node.
#[derive(FromQueryResult)]
struct VerdictRow {
    node_id: String,
    member_node_id: String,
    snapshot: serde_json::Value,
}

/// Read published counts without materializing verdict payloads. A verdict counts once per member
/// of the class of its node.
pub async fn counts(
    ids: &[Uuid],
    tx: &DatabaseTransaction,
) -> Result<Vec<SbomVerdictCounts>, Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let states = state(ids, tx).await?;
    let extraction = freshness::for_sboms(tx, ids).await?;
    let mut counts = HashMap::new();
    for row in tx.query_all_raw(sql(
        "SELECT v.sbom_id, count(*) FILTER (WHERE status='affected') affected, count(*) FILTER (WHERE status='fixed') fixed, count(*) FILTER (WHERE status='not_affected') not_affected, count(*) FILTER (WHERE status='under_investigation') under_investigation, count(*) FILTER (WHERE status='none') none, sum(remediation_count)::bigint remediations FROM correlation_verdict v LEFT JOIN correlation_node_class c ON c.sbom_id=v.sbom_id AND c.representative_node_id=v.node_id WHERE v.sbom_id=ANY($1) GROUP BY v.sbom_id",
        vec![ids.to_vec().into()],
    )).await? {
        let sbom_id = row.try_get("", "sbom_id")?;
        counts.insert(sbom_id, SbomVerdictCounts {
            sbom_id,
            affected: row.try_get::<i64>("", "affected")? as u64,
            fixed: row.try_get::<i64>("", "fixed")? as u64,
            not_affected: row.try_get::<i64>("", "not_affected")? as u64,
            under_investigation: row.try_get::<i64>("", "under_investigation")? as u64,
            none: row.try_get::<i64>("", "none")? as u64,
            remediations: row.try_get::<i64>("", "remediations")? as u64,
            ..Default::default()
        });
    }
    Ok(ids
        .iter()
        .map(|id| SbomVerdictCounts {
            sbom_id: *id,
            freshness: extraction.get(id).cloned().unwrap_or_default(),
            verdict_freshness: states.get(id).cloned().unwrap_or_default(),
            ..counts.get(id).cloned().unwrap_or_default()
        })
        .collect())
}

/// Outstanding work includes global revision mismatches, without expanding a queue first.
pub async fn lag(tx: &DatabaseTransaction) -> Result<VerdictLag, Error> {
    let lag = LagRow::find_by_statement(sql(
        "SELECT count(*) pending, count(*) FILTER (WHERE attempts > 0) failed, min(CASE WHEN completed_revision <> r.revision AND completed_input_revision = input_revision THEN r.changed_at WHEN completed_revision <> r.revision THEN least(queued_at,r.changed_at) ELSE queued_at END) oldest_pending_at FROM correlation_verdict_state s CROSS JOIN correlation_verdict_revision r WHERE completed_revision <> r.revision OR completed_input_revision <> input_revision",
        vec![],
    ))
    .one(tx)
    .await?
    .ok_or_else(|| DbErr::Custom("missing verdict backlog".into()))?;
    let current = CurrentRow::find_by_statement(sql(CURRENT_SQL, vec![]))
        .all(tx)
        .await?
        .into_iter()
        .map(|row| {
            Ok(CurrentSbom {
                progress: Some(WorkProgress {
                    done: u64::try_from(row.done)?,
                    total: u64::try_from(row.groups)?,
                }),
                ..row.sbom.into()
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(VerdictLag {
        pending: u64::try_from(lag.pending)?,
        failed: u64::try_from(lag.failed)?,
        oldest_pending_at: lag.oldest_pending_at,
        current,
    })
}

#[derive(FromQueryResult)]
struct LagRow {
    pending: i64,
    failed: i64,
    oldest_pending_at: Option<time::OffsetDateTime>,
}

/// An SBOM whose verdicts are being computed.
#[derive(FromQueryResult)]
struct CurrentRow {
    #[sea_orm(nested)]
    sbom: freshness::CurrentRow,
    groups: i64,
    done: i64,
}

/// The SBOMs whose verdicts are being computed. A row not updated for a while is left behind by a
/// crashed worker, as a batch takes seconds.
const CURRENT_SQL: &str = r#"
SELECT c.sbom_id, n.name, c.started_at, c.groups, c.done FROM correlation_verdict_current c
JOIN sbom s USING (sbom_id)
LEFT JOIN sbom_node n ON n.sbom_id = s.sbom_id AND n.node_id = s.node_id
WHERE c.updated_at > now() - interval '10 minutes'
ORDER BY c.started_at, c.sbom_id
"#;

/// Publishes the progress of a computation, outside of its transaction. Failing to do so doesn't
/// fail the computation.
struct Progress<'a> {
    db: &'a db::ReadWrite,
    sbom_id: Uuid,
}

impl<'a> Progress<'a> {
    /// Start a computation.
    async fn start(db: &'a db::ReadWrite, sbom_id: Uuid) -> Progress<'a> {
        let progress = Self { db, sbom_id };
        progress
            .publish(
                "INSERT INTO correlation_verdict_current(sbom_id, started_at, updated_at, groups, done) \
                 VALUES ($1, clock_timestamp(), clock_timestamp(), 0, 0) \
                 ON CONFLICT (sbom_id) DO UPDATE SET started_at = EXCLUDED.started_at, \
                 updated_at = EXCLUDED.updated_at, groups = 0, done = 0",
                vec![],
            )
            .await;
        progress
    }

    /// Update the number of groups, and the ones resolved.
    async fn update(&self, groups: usize, done: usize) {
        let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
        self.publish(
            "UPDATE correlation_verdict_current SET updated_at = clock_timestamp(), groups = $2, done = $3 \
             WHERE sbom_id = $1",
            vec![count(groups).into(), count(done).into()],
        )
        .await;
    }

    /// The computation ended, successfully or not.
    async fn finish(self) {
        self.publish(
            "DELETE FROM correlation_verdict_current WHERE sbom_id = $1",
            vec![],
        )
        .await;
    }

    async fn publish(&self, statement: &str, values: Vec<sea_orm::Value>) {
        let mut all = vec![self.sbom_id.into()];
        all.extend(values);
        let _ = self
            .db
            .execute_raw(sql(statement, all))
            .await
            .inspect_err(|err| tracing::warn!(sbom_id = %self.sbom_id, "failed to publish the verdict progress: {err}"));
    }
}

/// Claim one SBOM across all instances; failure rolls back its replacement but retains retries.
pub async fn run_step(db: &db::ReadWrite, config: &WorkerConfig) -> Result<bool, Error> {
    let tx = db.begin().await?;
    config.apply(&tx).await?;
    let revision = tx
        .query_one_raw(sql(
            "SELECT revision, resolver_version FROM correlation_verdict_revision",
            vec![],
        ))
        .await?
        .ok_or_else(|| DbErr::Custom("missing verdict revision".into()))?;
    if revision.try_get::<i32>("", "resolver_version")? != RESOLVER_VERSION {
        return Ok(false);
    }
    let revision: i64 = revision.try_get("", "revision")?;
    // Lock the parent before the work row, matching cascading deletion's lock order.
    // An exclusive row claim lets other workers skip this SBOM while permitting FK checks.
    // SBOMs waiting for an extraction are skipped: their evidence is about to be replaced, which
    // changes their inputs again.
    let Some(parent) = tx.query_one_raw(sql(
        "SELECT sbom.sbom_id FROM sbom JOIN correlation_verdict_state s USING(sbom_id) JOIN correlation_extraction_state e USING(sbom_id) WHERE retry_at <= now() AND (s.completed_revision <> $1 OR completed_input_revision <> input_revision) AND e.completed_revision = (SELECT revision FROM correlation_extraction_revision) ORDER BY retry_at,s.sbom_id LIMIT 1 FOR NO KEY UPDATE OF sbom SKIP LOCKED",
        vec![revision.into()],
    )).await? else { return Ok(false); };
    let id: Uuid = parent.try_get("", "sbom_id")?;
    let Some(row) = tx.query_one_raw(sql("SELECT sbom_id,input_revision FROM correlation_verdict_state WHERE sbom_id=$1 AND retry_at <= now() AND (completed_revision <> $2 OR completed_input_revision <> input_revision) FOR UPDATE SKIP LOCKED", vec![id.into(),revision.into()])).await? else { return Ok(false); };
    let id: Uuid = row.try_get("", "sbom_id")?;
    let input_revision: i64 = row.try_get("", "input_revision")?;
    let progress = Progress::start(db, id).await;
    let work = tx.begin().await?;
    let result = rebuild(
        id,
        revision,
        input_revision,
        BATCH_SIZE,
        Some(&progress),
        &work,
    )
    .await;
    match result {
        Ok(()) => {
            work.commit().await?;
        }
        Err(err) => {
            work.rollback().await?;
            tracing::warn!(sbom_id=%id, error=%err, "verdict computation failed; retrying");
            tx.execute_raw(sql("UPDATE correlation_verdict_state SET attempts=attempts+1,retry_at=clock_timestamp()+interval '30 seconds' WHERE sbom_id=$1", vec![id.into()])).await?;
        }
    }
    let committed = tx.commit().await;
    progress.finish().await;
    committed?;
    Ok(true)
}

/// Replace an SBOM's snapshot in bounded groups inside the caller's publication transaction.
async fn rebuild(
    id: Uuid,
    revision: i64,
    input_revision: i64,
    batch_size: usize,
    progress: Option<&Progress<'_>>,
    tx: &DatabaseTransaction,
) -> Result<(), Error> {
    correlation_verdict::Entity::delete_many()
        .filter(correlation_verdict::Column::SbomId.eq(id))
        .exec(tx)
        .await?;
    let service = CorrelationService::default();
    let request = ResolutionRequest {
        include_explanation: true,
        ..Default::default()
    };
    // the suppliers of the SBOM's packages are the same for every batch
    let mut snapshot = ProviderSnapshot::load_sboms(tx, &[id]).await?;
    // all groups at once: paging them would group and sort all the evidence for every page
    let groups = pagination::groups(id, &request)
        .into_model::<EvidenceGroup>()
        .all(tx)
        .instrument(info_span!("loading verdict groups"))
        .await?;
    let total = groups.len();
    if let Some(progress) = progress {
        progress.update(total, 0).await;
    }
    for (batch, groups) in groups.chunks(batch_size.max(1)).enumerate() {
        let evidence = pagination::evidence_for_groups(id, groups, tx).await?;
        let verdicts = service
            .verdicts(id, &request, &evidence, &mut snapshot, tx)
            .await?;
        let rows = verdicts
            .into_iter()
            .map(|verdict| {
                let distinct = verdict
                    .evidence
                    .iter()
                    .flat_map(|e| e.remediations.iter().map(move |r| (e.advisory_id, r)))
                    .collect::<HashSet<_>>();
                Ok(correlation_verdict::ActiveModel {
                    sbom_id: Set(id),
                    node_id: Set(verdict.component.node_id.clone()),
                    vulnerability_id: Set(verdict.vulnerability.id.clone()),
                    status: Set(verdict.status.into()),
                    remediation_count: Set(distinct.len() as i64),
                    snapshot: Set(serde_json::to_value(verdict).map_err(Error::MatchedValue)?),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if !rows.is_empty() {
            correlation_verdict::Entity::insert_many(rows)
                .exec(tx)
                .await?;
        }
        if let Some(progress) = progress {
            progress
                .update(total, total.min((batch + 1) * batch_size.max(1)))
                .await;
        }
    }
    let updated = tx.execute_raw(sql(
        "UPDATE correlation_verdict_state SET completed_revision=$2,completed_input_revision=$3,generation=$4,completed_at=clock_timestamp(),attempts=0 WHERE sbom_id=$1 AND input_revision=$3 AND EXISTS (SELECT 1 FROM correlation_verdict_revision WHERE revision=$2 AND resolver_version=$5)",
        vec![id.into(), revision.into(), input_revision.into(), Uuid::now_v7().into(), RESOLVER_VERSION.into()],
    )).await?;
    if updated.rows_affected() != 1 {
        return Err(Error::Conflict(
            "verdict inputs changed during computation".into(),
        ));
    }
    tx.execute_raw(sql(
        "UPDATE correlation_verdict_publication SET revision=revision+1",
        vec![],
    ))
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Publish explicitly inside fixture transactions; production only uses the durable worker.
#[cfg(test)]
pub(crate) async fn publish_for_test(id: Uuid, tx: &DatabaseTransaction) -> Result<(), Error> {
    publish_in_batches_for_test(id, BATCH_SIZE, tx).await
}

/// Like [`publish_for_test`], resolving the given number of groups at once.
#[cfg(test)]
pub(crate) async fn publish_in_batches_for_test(
    id: Uuid,
    batch_size: usize,
    tx: &DatabaseTransaction,
) -> Result<(), Error> {
    let row = tx.query_one_raw(sql("SELECT input_revision,revision FROM correlation_verdict_state CROSS JOIN correlation_verdict_revision WHERE sbom_id=$1", vec![id.into()])).await?
        .ok_or_else(|| DbErr::Custom("missing verdict state".into()))?;
    rebuild(
        id,
        row.try_get("", "revision")?,
        row.try_get("", "input_revision")?,
        batch_size,
        None,
        tx,
    )
    .await
}
