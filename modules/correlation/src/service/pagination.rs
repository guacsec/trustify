//! Pages select complete verdict groups, never individual evidence rows.
use super::*;

use sea_orm::{
    ExprTrait, QueryOrder, QuerySelect, QueryTrait, Select, Value,
    sea_query::{Expr, Order},
};
use trustify_common::{
    db::{limiter::LimiterTrait, pagination_cache::PaginationCache},
    model::{PaginatedResults, Pagination},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, FromQueryResult)]
pub(super) struct EvidenceGroup {
    pub(super) node_id: String,
    pub(super) vulnerability_id: String,
}

/// Stored statements remain facts; only current advisories participate in resolution.
fn eligible_evidence(sbom_id: Uuid) -> Select<correlation_evidence::Entity> {
    correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::SbomId.eq(sbom_id))
        .filter(
            correlation_evidence::Column::AdvisoryId.in_subquery(
                advisory::Entity::find()
                    .select_only()
                    .column(advisory::Column::Id)
                    .filter(advisory::Column::Deprecated.eq(false))
                    .into_query(),
            ),
        )
}

/// Select evidence for an SBOM, applying optional node and vulnerability filters.
///
/// The evidence of a node is the one of its class' representative.
pub(super) fn evidence_query(
    sbom_id: Uuid,
    request: &ResolutionRequest,
) -> Select<correlation_evidence::Entity> {
    let mut query = eligible_evidence(sbom_id);
    if let Some(node) = &request.node_id {
        query = query.filter(
            Expr::col(correlation_evidence::Column::NodeId)
                .eq(class::representative(sbom_id, node)),
        );
    }
    if let Some(vulnerability) = &request.vulnerability_id {
        query = query.filter(correlation_evidence::Column::VulnerabilityId.eq(vulnerability));
    }
    query
}

/// Select distinct verdict keys in case-sensitive node and vulnerability order.
pub(super) fn groups(
    sbom_id: Uuid,
    request: &ResolutionRequest,
) -> Select<correlation_evidence::Entity> {
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
pub(super) async fn evidence_for_groups(
    sbom_id: Uuid,
    groups: &[EvidenceGroup],
    connection: &DatabaseTransaction,
) -> Result<Vec<correlation_evidence::Model>, Error> {
    if groups.is_empty() {
        return Ok(Vec::new());
    }
    let (nodes, vulnerabilities): (Vec<_>, Vec<_>) = groups
        .iter()
        .map(|group| (group.node_id.clone(), group.vulnerability_id.clone()))
        .unzip();
    Ok(eligible_evidence(sbom_id)
        .filter(Expr::cust_with_values(
            "(node_id, vulnerability_id) IN (SELECT * FROM unnest($1::text[], $2::text[]))",
            [Value::from(nodes), Value::from(vulnerabilities)],
        ))
        .order_by_asc(correlation_evidence::Column::Id)
        .all(connection)
        .await?)
}

impl CorrelationService {
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
        let evidence = eligible_evidence(sbom_id)
            .select_only()
            .column(correlation_evidence::Column::NodeId)
            .filter(
                // the evidence of the node's class
                Expr::col((
                    correlation_evidence::Entity,
                    correlation_evidence::Column::NodeId,
                ))
                .eq(Expr::cust(
                    "coalesce((SELECT c.representative_node_id FROM correlation_node_class c \
                     WHERE c.sbom_id = sbom_node.sbom_id AND c.node_id = sbom_node.node_id), \
                     sbom_node.node_id)",
                )),
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
}
