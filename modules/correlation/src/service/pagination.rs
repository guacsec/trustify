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

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, FromQueryResult)]
struct EvidenceGroup {
    node_id: String,
    vulnerability_id: String,
}

/// Select evidence for an SBOM, applying optional node and vulnerability filters.
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

/// Select distinct verdict keys in case-sensitive node and vulnerability order.
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

/// Load all evidence for the selected verdict keys, ordered by evidence ID.
/// An empty selection returns no evidence without querying the database.
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RemediationKey {
    group: EvidenceGroup,
    advisory_id: Uuid,
    category: &'static str,
    details: Option<String>,
    url: Option<String>,
}

impl RemediationKey {
    /// Build the distinct remediation identity used for ordering and deduplication.
    fn new(group: EvidenceGroup, advisory_id: Uuid, remediation: &EvidenceRemediation) -> Self {
        Self {
            group,
            advisory_id,
            category: remediation.category.into(),
            details: remediation.details.clone(),
            url: remediation.url.clone(),
        }
    }
}

/// Collect distinct source-linked identities before slicing the requested page in memory.
async fn remediation_keys(
    evidence: &[correlation_evidence::Model],
    connection: &DatabaseTransaction,
) -> Result<Vec<RemediationKey>, Error> {
    let mut remediations = load_evidence_remediations(evidence, connection).await?;
    let mut ordered = BTreeSet::new();
    for row in evidence {
        for remediation in remediations.remove(&row.id).unwrap_or_default() {
            ordered.insert(RemediationKey::new(
                EvidenceGroup {
                    node_id: row.node_id.clone(),
                    vulnerability_id: row.vulnerability_id.clone(),
                },
                row.advisory_id,
                &remediation,
            ));
        }
    }
    Ok(ordered.into_iter().collect())
}

impl CorrelationService {
    /// Page verdict keys in SQL and resolve their complete evidence groups.
    /// Filters apply before pagination; the optional cached total counts verdict groups.
    /// Invalid pagination limits return an error before fetching evidence.
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

    /// Page components with no evidence in the SBOM, excluding its root node.
    /// The optional node filter applies before pagination; identifiers are loaded only
    /// for selected components. Totals are optional and cached, and invalid limits fail.
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
                .map(|n| n.node_id.as_str())
                .collect::<Vec<_>>();
            let identifiers = self
                .extractors
                .component_identifiers(sbom_id, Some(&nodes), connection)
                .await?;
            selected
                .items
                .into_iter()
                .map(|n| build_component_ref(n.node_id, n.name, &identifiers))
                .collect()
        };
        Ok(PaginatedResults { items, total })
    }

    /// Slice distinct remediation identities in memory, resolving only selected verdict groups.
    /// Filters apply before collection and slicing; the optional uncached total counts
    /// distinct identities. Zero-limit requests skip verdict resolution, and requests
    /// without a total also skip identity loading. Invalid pagination limits fail.
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
        if paginated.limit() == 0 && !paginated.total() {
            return Ok(PaginatedResults::default());
        }
        let mut evidence = evidence_query(sbom_id, request)
            .order_by_asc(correlation_evidence::Column::Id)
            .all(connection)
            .await?;
        let keys = remediation_keys(&evidence, connection).await?;
        let page = paginated.paginate_array(&keys);
        if page.items.is_empty() {
            return Ok(PaginatedResults {
                items: Vec::new(),
                total: page.total,
            });
        }
        let selected = page
            .items
            .iter()
            .map(|key| {
                (
                    key.group.node_id.as_str(),
                    key.group.vulnerability_id.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        evidence.retain(|row| {
            selected.contains(&(row.node_id.as_str(), row.vulnerability_id.as_str()))
        });
        let selected = page.items.into_iter().collect::<BTreeSet<_>>();
        let mut items = BTreeMap::new();
        for verdict in self
            .verdicts(sbom_id, request, &evidence, connection)
            .await?
        {
            let group = EvidenceGroup {
                node_id: verdict.component.node_id.clone(),
                vulnerability_id: verdict.vulnerability.id.clone(),
            };
            for advisory in verdict.evidence {
                for remediation in advisory.remediations {
                    let key =
                        RemediationKey::new(group.clone(), advisory.advisory_id, &remediation);
                    if selected.contains(&key) {
                        items.insert(
                            key,
                            SbomRemediation {
                                component: verdict.component.clone(),
                                vulnerability: verdict.vulnerability.id.clone(),
                                status: verdict.status,
                                remediation,
                                advisory_id: advisory.advisory_id,
                                advisory_identifier: advisory.advisory_identifier.clone(),
                                advisory_type: advisory.advisory_type.clone(),
                            },
                        );
                    }
                }
            }
        }
        Ok(PaginatedResults {
            items: items.into_values().collect(),
            total: page.total,
        })
    }
}
