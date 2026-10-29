//! Durable default verdict snapshots. Reads never run the resolver.
use super::{
    CorrelationService, freshness,
    pagination::{self, EvidenceGroup},
};
use crate::{
    error::Error,
    model::{
        ResolutionRequest, SbomVerdictCounts, SbomVerdictPage, VerdictFreshness, VerdictLag,
        VerdictStatus, VerdictSummary,
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, ExprTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait, sea_query::Expr,
};
use std::collections::{HashMap, HashSet};
use trustify_common::{
    db::{self, limiter::LimiterTrait, pagination_cache::PaginationCache, sql},
    model::Pagination,
};
use trustify_entity::{correlation_verdict, correlation_verdict_freshness};
use uuid::Uuid;

/// Bump in a migration together with changes to the default resolver's semantics.
const RESOLVER_VERSION: i32 = 1;
const BATCH_SIZE: u64 = 128;

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
        let mut query = correlation_verdict::Entity::find()
            .filter(correlation_verdict::Column::SbomId.eq(sbom_id));
        if let Some(node) = &request.node_id {
            query = query.filter(correlation_verdict::Column::NodeId.eq(node));
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
            .order_by_asc(correlation_verdict::Column::NodeId)
            .order_by_asc(correlation_verdict::Column::VulnerabilityId)
            .limiting(tx, paginated, cache)?
            .fetch()
            .await?;
        let total = selected.total.requested(paginated.total()).await?;
        let items = selected
            .items
            .into_iter()
            .map(|row| {
                let mut verdict: VerdictSummary =
                    serde_json::from_value(row.snapshot).map_err(Error::MatchedValue)?;
                if !request.include_explanation {
                    verdict.resolution.explanation = None;
                }
                Ok(verdict)
            })
            .collect::<Result<_, Error>>()?;
        Ok(SbomVerdictPage {
            items,
            total,
            freshness,
        })
    }
}

/// Read published counts without materializing verdict payloads.
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
        "SELECT sbom_id, count(*) FILTER (WHERE status='affected') affected, count(*) FILTER (WHERE status='fixed') fixed, count(*) FILTER (WHERE status='not_affected') not_affected, count(*) FILTER (WHERE status='under_investigation') under_investigation, count(*) FILTER (WHERE status='none') none, sum(remediation_count)::bigint remediations FROM correlation_verdict WHERE sbom_id=ANY($1) GROUP BY sbom_id",
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
    let row = tx.query_one_raw(sql(
        "SELECT count(*) pending, count(*) FILTER (WHERE attempts > 0) failed, min(CASE WHEN completed_revision <> r.revision AND completed_input_revision = input_revision THEN r.changed_at WHEN completed_revision <> r.revision THEN least(queued_at,r.changed_at) ELSE queued_at END) oldest_pending_at FROM correlation_verdict_state s CROSS JOIN correlation_verdict_revision r WHERE completed_revision <> r.revision OR completed_input_revision <> input_revision",
        vec![],
    )).await?.ok_or_else(|| DbErr::Custom("missing verdict backlog".into()))?;
    Ok(VerdictLag {
        pending: row.try_get::<i64>("", "pending")? as u64,
        failed: row.try_get::<i64>("", "failed")? as u64,
        oldest_pending_at: row.try_get("", "oldest_pending_at")?,
    })
}

/// Claim one SBOM across all instances; failure rolls back its replacement but retains retries.
pub async fn run_step(db: &db::ReadWrite) -> Result<bool, Error> {
    let tx = db.begin().await?;
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
    let Some(parent) = tx.query_one_raw(sql(
        "SELECT sbom.sbom_id FROM sbom JOIN correlation_verdict_state s USING(sbom_id) WHERE retry_at <= now() AND (completed_revision <> $1 OR completed_input_revision <> input_revision) ORDER BY retry_at,s.sbom_id LIMIT 1 FOR NO KEY UPDATE OF sbom SKIP LOCKED",
        vec![revision.into()],
    )).await? else { return Ok(false); };
    let id: Uuid = parent.try_get("", "sbom_id")?;
    let Some(row) = tx.query_one_raw(sql("SELECT sbom_id,input_revision FROM correlation_verdict_state WHERE sbom_id=$1 AND retry_at <= now() AND (completed_revision <> $2 OR completed_input_revision <> input_revision) FOR UPDATE SKIP LOCKED", vec![id.into(),revision.into()])).await? else { return Ok(false); };
    let id: Uuid = row.try_get("", "sbom_id")?;
    let input_revision: i64 = row.try_get("", "input_revision")?;
    let work = tx.begin().await?;
    match rebuild(id, revision, input_revision, &work).await {
        Ok(()) => {
            work.commit().await?;
        }
        Err(err) => {
            work.rollback().await?;
            tracing::warn!(sbom_id=%id, error=%err, "verdict computation failed; retrying");
            tx.execute_raw(sql("UPDATE correlation_verdict_state SET attempts=attempts+1,retry_at=clock_timestamp()+interval '30 seconds' WHERE sbom_id=$1", vec![id.into()])).await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// Replace an SBOM's snapshot in bounded groups inside the caller's publication transaction.
async fn rebuild(
    id: Uuid,
    revision: i64,
    input_revision: i64,
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
    let mut cursor: Option<EvidenceGroup> = None;
    loop {
        let mut query = pagination::groups(id, &request);
        if let Some(cursor) = &cursor {
            query = query.filter(Expr::cust_with_values(
                "(node_id COLLATE \"C\", vulnerability_id COLLATE \"C\") > ($1, $2)",
                [cursor.node_id.clone(), cursor.vulnerability_id.clone()],
            ));
        }
        let groups = query
            .limit(BATCH_SIZE)
            .into_model::<EvidenceGroup>()
            .all(tx)
            .await?;
        if groups.is_empty() {
            break;
        }
        let evidence = pagination::evidence_for_groups(id, &groups, tx).await?;
        let verdicts = service.verdicts(id, &request, &evidence, tx).await?;
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
        cursor = groups.last().cloned();
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
    let row = tx.query_one_raw(sql("SELECT input_revision,revision FROM correlation_verdict_state CROSS JOIN correlation_verdict_revision WHERE sbom_id=$1", vec![id.into()])).await?
        .ok_or_else(|| DbErr::Custom("missing verdict state".into()))?;
    rebuild(
        id,
        row.try_get("", "revision")?,
        row.try_get("", "input_revision")?,
        tx,
    )
    .await
}
