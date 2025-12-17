use crate::{
    Error,
    service::{ResolvedSbom, resolve_rh_external_sbom_ancestors},
};
use async_recursion::async_recursion;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, QueryFilter, QuerySelect, Select,
    prelude::DateTimeWithTimeZone,
};
use std::collections::HashSet;
use trustify_entity::{package_relates_to_package, sbom, sbom_node, sbom_package_cpe_ref};
use uuid::Uuid;

#[derive(Debug, Clone, FromQueryResult)]
pub struct Row {
    /// The matched SBOM
    pub sbom_id: Uuid,
    /// The node inside the matched SBOM
    pub node_id: String,
    /// name of the matched node
    pub name: String,
    /// publish time of the SBOM that matched
    pub published: DateTimeWithTimeZone,
}

#[derive(Debug, Clone)]
pub struct RankedSbom {
    pub matched_sbom_id: Uuid,
    #[allow(dead_code)] // good for debugging
    pub matched_name: String,
    #[allow(dead_code)] // good for debugging
    pub ancestor_sbom_id: Uuid,
    pub cpe_id: Uuid,
    pub sbom_date: DateTimeWithTimeZone,
    pub rank: Option<usize>,
}

/// prepare a select statement, returning [`Row`]s.
pub fn select() -> Select<sbom_node::Entity> {
    sbom_node::Entity::find()
        .select_only()
        .column(sbom_node::Column::SbomId)
        .column(sbom_node::Column::NodeId)
        .column(sbom_node::Column::Name)
        .column(sbom::Column::Published)
        .left_join(sbom::Entity)
}

#[async_recursion]
async fn resolve_all_ancestors<C>(
    sbom_sbom_id: Uuid,
    sbom_node_ref: String,
    connection: &C,
    visited: &mut HashSet<Uuid>,
) -> Result<Vec<ResolvedSbom>, Error>
where
    C: ConnectionTrait + Send + Sync,
{
    if !visited.insert(sbom_sbom_id) {
        log::debug!(
            "Cycle detected for SBOM {}, skipping recursion.",
            sbom_sbom_id
        );
        return Ok(vec![]);
    }
    let mut all_resolved_sboms = vec![];

    // 1. Execute query and handle the Result safely ONCE.
    // usage: resolve_rh_external_sbom_ancestors likely returns Result<Vec<...>, Error>
    let direct_ancestors = resolve_rh_external_sbom_ancestors(
        sbom_sbom_id,
        sbom_node_ref,
        connection, // Pass the reference directly (no need to clone if inner fn takes &C)
    )
    .await?;

    for ancestor in direct_ancestors {
        all_resolved_sboms.push(ancestor.clone());

        let top_package_of_sbom = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(ancestor.sbom_id))
            .filter(package_relates_to_package::Column::RightNodeId.eq(ancestor.node_id))
            .all(connection)
            .await?;

        for package in top_package_of_sbom {
            let deep_ancestors =
                resolve_all_ancestors(package.sbom_id, package.left_node_id, connection, visited)
                    .await?;

            all_resolved_sboms.extend(deep_ancestors);
        }
    }

    Ok(all_resolved_sboms)
}

/// Resolve CPEs for matched SBOMs.
///
/// The CPEs of an SBOM are the CPEs of the describing component.
///
/// ## Input
///
/// * `rows`: the nodes matching the initial search
///
/// ## Output
///
/// * A Vec of nodes matching, filled with their CPE.
///
pub async fn resolve_sbom_cpes(
    connection: &(impl ConnectionTrait + Send),
    rows: Vec<Row>,
) -> Result<Vec<RankedSbom>, Error> {
    // step 2 - get CPEs (by resolving)
    let mut matched_sboms = Vec::new();
    let mut visited = HashSet::new();

    for matched in rows {
        // find top level package of matched sbom
        let top_package_of_sbom = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(matched.sbom_id))
            .filter(package_relates_to_package::Column::RightNodeId.eq(matched.node_id))
            .all(connection)
            .await?;

        // resolve ancestor externally linked sboms
        let mut cpes = HashSet::new();
        let mut top_ancestor_sbom = None;

        for package in top_package_of_sbom {
            // resolve_all_ancestors is recursive
            let ancestor_sboms = resolve_all_ancestors(
                package.sbom_id,
                package.left_node_id,
                connection,
                &mut visited,
            )
            .await?;
            log::debug!("ancestor sboms: {:?}", ancestor_sboms);

            top_ancestor_sbom = ancestor_sboms
                .last()
                .map(|a| a.sbom_id)
                .or(Some(matched.sbom_id));

            cpes.extend(
                sbom_package_cpe_ref::Entity::find()
                    .filter(sbom_package_cpe_ref::Column::SbomId.eq(top_ancestor_sbom))
                    .select_only()
                    .column(sbom_package_cpe_ref::Column::CpeId)
                    .into_tuple::<Uuid>()
                    .all(connection)
                    .await?,
            );
        }

        matched_sboms.extend(cpes.into_iter().map(|cpe_id| RankedSbom {
            matched_sbom_id: matched.sbom_id,
            matched_name: matched.name.clone(),
            ancestor_sbom_id: top_ancestor_sbom.unwrap(),
            cpe_id,
            sbom_date: matched.published,
            rank: None,
        }));
    }

    Ok(matched_sboms)
}

/// emulate SQL RANK which partitions vec RankedSBOM on cpe_id and date
///
/// The input is a (possibly) unsorted Vec of RankedSboms. The `rank` field may be empty and
/// will be filled when the function returns.
///
/// As a side effect, the Vec will be sorted by cpe_id, then sbom_date
pub fn apply_rank(items: &mut [RankedSbom]) {
    items.sort_by(|a, b| {
        a.cpe_id
            .cmp(&b.cpe_id) // Partition 1
            .then(b.sbom_date.cmp(&a.sbom_date)) // Order: DESC (b vs a)
    });

    let mut current_rank = 1;

    // We iterate with indices so we can compare [i] with [i-1]
    for i in 0..items.len() {
        // If it's the first item, it's automatically Rank 1
        if i == 0 {
            items[i].rank = Some(1);
            continue;
        }

        let prev = &items[i - 1];
        let curr = &items[i];

        // Check if we are in the same "Partition" (CPE)
        let same_partition = curr.cpe_id == prev.cpe_id;

        if same_partition {
            // If dates are exact same, they get same rank.
            if curr.sbom_date == prev.sbom_date {
                items[i].rank = items[i - 1].rank;
            } else {
                // Standard increment
                current_rank += 1;
                items[i].rank = Some(current_rank);
            }
        } else {
            // New partition detected! Reset rank.
            current_rank = 1;
            items[i].rank = Some(1);
        }
    }
}
