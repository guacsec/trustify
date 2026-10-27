//! Pages select complete verdict groups, never individual evidence rows.
use super::*;
use crate::model::SbomRemediation;
use sea_orm::{
    Condition, ExprTrait, QueryOrder, QuerySelect, QueryTrait, Select,
    sea_query::{Expr, Order},
};
use trustify_common::{
    db::{
        limiter::{LimiterAsModelTrait, LimiterTrait},
        pagination_cache::PaginationCache,
    },
    model::{PaginatedResults, Pagination},
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, FromQueryResult)]
struct EvidenceGroup {
    node_id: String,
    vulnerability_id: String,
}

fn evidence_query(
    sbom_id: Uuid,
    request: &ResolutionRequest,
) -> Select<correlation_evidence::Entity> {
    let mut query = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id));
    if let Some(node) = &request.node_id {
        query = query.filter(correlation_evidence::Column::NodeId.eq(node));
    }
    if let Some(vulnerability) = &request.vulnerability_id {
        query = query.filter(correlation_evidence::Column::VulnerabilityId.eq(vulnerability));
    }
    query
}

fn groups(sbom_id: Uuid, request: &ResolutionRequest) -> Select<correlation_evidence::Entity> {
    evidence_query(sbom_id, request)
        .select_only()
        .column(correlation_evidence::Column::NodeId)
        .column(correlation_evidence::Column::VulnerabilityId)
        .group_by(correlation_evidence::Column::NodeId)
        .group_by(correlation_evidence::Column::VulnerabilityId)
        .order_by(Expr::cust("node_id COLLATE \"C\""), Order::Asc)
        .order_by(Expr::cust("vulnerability_id COLLATE \"C\""), Order::Asc)
}

async fn evidence_for_groups(
    sbom_id: Uuid,
    groups: &[EvidenceGroup],
    connection: &DatabaseTransaction,
) -> Result<Vec<correlation_evidence::Model>, Error> {
    if groups.is_empty() {
        return Ok(Vec::new());
    }
    let mut selected = Condition::any();
    for group in groups {
        selected = selected.add(
            Condition::all()
                .add(correlation_evidence::Column::NodeId.eq(&group.node_id))
                .add(correlation_evidence::Column::VulnerabilityId.eq(&group.vulnerability_id)),
        );
    }
    Ok(correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .filter(selected)
        .order_by_asc(correlation_evidence::Column::Id)
        .all(connection)
        .await?)
}

/// The order is the serialized category name, independent of enum declaration order.
fn category_key(category: crate::model::RemediationCategory) -> &'static str {
    use crate::model::RemediationCategory::*;
    match category {
        VendorFix => "vendor_fix",
        Workaround => "workaround",
        Mitigation => "mitigation",
        NoFixPlanned => "no_fix_planned",
        NoneAvailable => "none_available",
        WillNotFix => "will_not_fix",
    }
}

#[derive(Clone)]
struct RemediationKey {
    group: EvidenceGroup,
    advisory_id: Uuid,
    remediation: EvidenceRemediation,
}

impl CorrelationService {
    pub async fn verdict_page(
        &self,
        sbom_id: Uuid,
        request: &ResolutionRequest,
        paginated: impl Pagination,
        cache: &PaginationCache,
        connection: &DatabaseTransaction,
    ) -> Result<PaginatedResults<VerdictSummary>, Error> {
        let selected = groups(sbom_id, request)
            .limiting_as::<EvidenceGroup>(connection, paginated, cache)?
            .fetch()
            .await?;
        let total = selected.total.requested(paginated.total()).await?;
        let evidence = evidence_for_groups(sbom_id, &selected.items, connection).await?;
        let items = self
            .verdicts(sbom_id, request, &evidence, connection)
            .await?;
        Ok(PaginatedResults { items, total })
    }

    pub async fn unmatched_page(
        &self,
        sbom_id: Uuid,
        node_id: Option<&str>,
        paginated: impl Pagination,
        cache: &PaginationCache,
        connection: &DatabaseTransaction,
    ) -> Result<PaginatedResults<ComponentRef>, Error> {
        let evidence = correlation_evidence::Entity::find()
            .select_only()
            .column(correlation_evidence::Column::NodeId)
            .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
            .filter(
                Expr::col((
                    correlation_evidence::Entity,
                    correlation_evidence::Column::NodeId,
                ))
                .equals((sbom_node::Entity, sbom_node::Column::NodeId)),
            );
        let root = sbom::Entity::find()
            .select_only()
            .column(sbom::Column::NodeId)
            .filter(sbom::Column::SbomId.eq(sbom_id));
        let mut query = sbom_node::Entity::find()
            .filter(sbom_node::Column::SbomId.eq(sbom_id))
            .filter(Expr::exists(evidence.into_query()).not())
            .filter(sbom_node::Column::NodeId.not_in_subquery(root.into_query()));
        if let Some(node) = node_id {
            query = query.filter(sbom_node::Column::NodeId.eq(node));
        }
        let selected = query
            .order_by(Expr::cust("sbom_node.node_id COLLATE \"C\""), Order::Asc)
            .limiting(connection, paginated, cache)?
            .fetch()
            .await?;
        let total = selected.total.requested(paginated.total()).await?;
        let items = if selected.items.is_empty() {
            Vec::new()
        } else {
            let nodes = selected
                .items
                .iter()
                .map(|n| n.node_id.clone())
                .collect::<Vec<_>>();
            let identifiers = self
                .extractors
                .component_identifiers_scoped(sbom_id, Some(&nodes), connection)
                .await?;
            selected
                .items
                .into_iter()
                .map(|n| build_component_ref(n.node_id, n.name, &identifiers))
                .collect()
        };
        Ok(PaginatedResults { items, total })
    }

    /// Enumerate compact identities in bounded batches. Resolution and UI enrichment happen only
    /// after selecting the requested remediation rows. The legacy source matching stays shared.
    async fn remediation_keys(
        &self,
        sbom_id: Uuid,
        request: &ResolutionRequest,
        offset: u64,
        limit: u64,
        count_all: bool,
        connection: &DatabaseTransaction,
    ) -> Result<(Vec<RemediationKey>, u64), Error> {
        let mut items = Vec::new();
        let mut seen = 0u64;
        let mut group_offset = 0;
        if limit == 0 && !count_all {
            return Ok((items, seen));
        }
        loop {
            let batch = groups(sbom_id, request)
                .offset(group_offset)
                .limit(100)
                .into_model::<EvidenceGroup>()
                .all(connection)
                .await?;
            if batch.is_empty() {
                break;
            }
            group_offset += batch.len() as u64;
            let evidence = evidence_for_groups(sbom_id, &batch, connection).await?;
            let mut remediations = load_evidence_remediations(&evidence, connection).await?;
            let mut ordered = BTreeMap::new();
            for row in &evidence {
                for remediation in remediations.remove(&row.id).unwrap_or_default() {
                    let group = EvidenceGroup {
                        node_id: row.node_id.clone(),
                        vulnerability_id: row.vulnerability_id.clone(),
                    };
                    ordered.insert(
                        (
                            group,
                            row.advisory_id,
                            category_key(remediation.category),
                            remediation.details.clone(),
                            remediation.url.clone(),
                        ),
                        remediation,
                    );
                }
            }
            for ((group, advisory_id, _, _, _), remediation) in ordered {
                if seen >= offset && (items.len() as u64) < limit {
                    items.push(RemediationKey {
                        group,
                        advisory_id,
                        remediation,
                    });
                }
                seen += 1;
                if !count_all && (items.len() as u64) == limit {
                    return Ok((items, seen));
                }
            }
        }
        Ok((items, seen))
    }

    pub async fn remediation_page(
        &self,
        sbom_id: Uuid,
        request: &ResolutionRequest,
        paginated: impl Pagination,
        cache: &PaginationCache,
        connection: &DatabaseTransaction,
    ) -> Result<PaginatedResults<SbomRemediation>, Error> {
        // Use the common limiter for validation, including the configured maximum and zero.
        let _validated =
            groups(sbom_id, request).limiting_as::<EvidenceGroup>(connection, paginated, cache)?;
        let total = if paginated.total() {
            let statement = groups(sbom_id, request).build(DbBackend::Postgres);
            let key = format!(
                "correlation-remediations:{}|{:?}",
                statement.sql, statement.values
            );
            Some(
                cache
                    .cached_total(key, async || {
                        self.remediation_keys(sbom_id, request, 0, 0, true, connection)
                            .await
                            .map(|(_, count)| count)
                            .map_err(|err| sea_orm::DbErr::Custom(err.to_string()))
                    })
                    .await?,
            )
        } else {
            None
        };
        let (keys, _) = self
            .remediation_keys(
                sbom_id,
                request,
                paginated.offset(),
                paginated.limit(),
                false,
                connection,
            )
            .await?;
        let selected = keys
            .iter()
            .map(|key| key.group.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let evidence = evidence_for_groups(sbom_id, &selected, connection).await?;
        let verdicts = self
            .verdicts(sbom_id, request, &evidence, connection)
            .await?
            .into_iter()
            .map(|v| ((v.component.node_id.clone(), v.vulnerability.id.clone()), v))
            .collect::<HashMap<_, _>>();
        let mut items = Vec::with_capacity(keys.len());
        for key in keys {
            let verdict = verdicts
                .get(&(key.group.node_id, key.group.vulnerability_id))
                .ok_or(Error::IncompleteRemediationEvidence)?;
            let advisory = verdict
                .evidence
                .iter()
                .find(|e| e.advisory_id == key.advisory_id)
                .ok_or(Error::IncompleteRemediationEvidence)?;
            items.push(SbomRemediation {
                component: verdict.component.clone(),
                vulnerability: verdict.vulnerability.id.clone(),
                status: verdict.status,
                remediation: key.remediation,
                advisory_id: key.advisory_id,
                advisory_identifier: advisory.advisory_identifier.clone(),
                advisory_type: advisory.advisory_type.clone(),
            });
        }
        Ok(PaginatedResults { items, total })
    }
}

#[cfg(test)]
mod tests;
