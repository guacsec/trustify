use crate::{
    Error,
    service::{ResolvedSbom, resolve_rh_external_sbom_ancestors},
};
use async_recursion::async_recursion;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    RelationTrait, Select, prelude::DateTimeWithTimeZone,
};
use sea_query::JoinType;
use std::collections::HashSet;
use trustify_entity::relationship::Relationship;
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
    pub top_ancestor_sbom: Uuid,
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

/// Recursively resolves external SBOM references to build a complete dependency graph across multiple SBOM files.
///
/// This function performs a **Depth-First Search (DFS)** starting from a specific node in a specific SBOM.
/// It looks for "external references" (pointers to other SBOMs), resolves them, and then recursively
/// traverses up the tree of the referenced SBOMs to find further ancestors.
///
/// # Arguments
///
/// * `sbom_id` - The UUID of the current SBOM being inspected.
/// * `node_id` - The node ID within the current SBOM to search for external ancestors.
/// * `connection` - The database connection.
/// * `visited` - A `HashSet` used to track visited SBOM UUIDs and prevent infinite recursion in cyclic graphs.
///
/// # Returns
///
/// Returns a `Result` containing:
/// * `Vec<ResolvedSbom>`: A flattened list of all resolved external SBOM ancestors found recursively.
/// * `Error`: If a database error occurs.
#[async_recursion]
async fn find_external_refs<C>(
    sbom_id: Uuid,
    node_id: String,
    connection: &C,
    visited: &mut HashSet<Uuid>,
) -> Result<Vec<ResolvedSbom>, Error>
where
    C: ConnectionTrait + Send,
{
    if !visited.insert(sbom_id) {
        log::debug!("Cycle detected for SBOM {}, skipping recursion.", sbom_id);
        return Ok(vec![]);
    }
    let mut all_resolved_sboms = vec![];

    // 1. Execute query and handle the Result safely ONCE.
    // usage: resolve_rh_external_sbom_ancestors likely returns Result<Vec<...>, Error>
    let direct_ancestors = resolve_rh_external_sbom_ancestors(sbom_id, node_id, connection).await?;

    for ancestor in direct_ancestors {
        all_resolved_sboms.push(ancestor.clone());

        let top_package_of_sbom = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(ancestor.sbom_id))
            .filter(package_relates_to_package::Column::RightNodeId.eq(ancestor.node_id))
            .all(connection)
            .await?;

        for package in top_package_of_sbom {
            let deep_ancestors =
                find_external_refs(package.sbom_id, package.left_node_id, connection, visited)
                    .await?;

            all_resolved_sboms.extend(deep_ancestors);
        }
    }

    Ok(all_resolved_sboms)
}

/// Get all CPEs of the "describing component" of an SBOM
///
/// This means: all CPEs of all nodes which have the SBOM's node ID on the right side of a "describes" relationship
async fn describing_cpes(
    connection: &(impl ConnectionTrait + Send),
    sbom_id: Uuid,
) -> Result<Vec<Uuid>, Error> {
    Ok(sbom_package_cpe_ref::Entity::find()
        .distinct()
        .select_only()
        .column(sbom_package_cpe_ref::Column::CpeId)
        .filter(sbom_package_cpe_ref::Column::SbomId.eq(sbom_id))
        .join(JoinType::Join, sbom_package_cpe_ref::Relation::Sbom.def())
        .join(
            JoinType::Join,
            sbom::Relation::PackageRelatesToPackages.def(),
        )
        .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Describes))
        .into_tuple::<Uuid>()
        .all(connection)
        .await?)
}

/// Retrieves lineage (ancestors) of a specific node within an SBOM graph.
///
/// This function performs an iterative upstream traversal starting from the `start_node_id`.
/// It walks the `package_relates_to_package` table from Child to Parent until it reaches
/// a root node (no further parents) or hits a hard-coded recursion depth limit.
///
/// # Arguments
///
/// * `sbom_id` - The unique identifier of the SBOM to scope the search within.
/// * `start_node_id` - The identifier of the child node to begin the traversal from.
/// * `connection` - The database connection used to execute the queries.
///
/// # Returns
///
/// Returns a `Result` containing:
/// * `Vec<package_relates_to_package::Model>`: A vector of relationship entities ordered
///   from the immediate parent up to the root ancestor.
/// * `DbErr`: If a database error occurs during traversal.
///
/// # Behavior & Limitations
///
/// * **Single Path Traversal**: If a node has multiple parents (DAG structure), this function
///   currently selects the *first* parent returned by the database and ignores others.
/// * **Cycle Protection**: Enforces a `MAX_DEPTH` of 100 to prevents infinite loops in
///   cyclic graphs (e.g., A -> B -> A).
pub async fn find_node_ancestors<C: ConnectionTrait>(
    sbom_id: Uuid,
    start_node_id: String,
    connection: &C,
) -> Result<Vec<package_relates_to_package::Model>, DbErr> {
    let mut ancestors = Vec::new();
    let mut current_child_id = start_node_id;

    // guard to prevent infinite loops ( eg. cycles A->B->A)
    // TODO: we may need to do more for infinite loop handling in pure sql
    let mut depth = 0;
    const MAX_DEPTH: usize = 100;

    loop {
        // Find relationship where current node is the CHILD (Right Side).
        // The LEFT side is the parent/container node.
        let parents = package_relates_to_package::Entity::find()
            .filter(package_relates_to_package::Column::SbomId.eq(sbom_id))
            .filter(package_relates_to_package::Column::RightNodeId.eq(&current_child_id))
            .all(connection)
            .await?;

        // 1. Base Case: No parents found. We are at the top.
        if parents.is_empty() {
            break;
        }

        let parent_rel = &parents[0];
        ancestors.push(parent_rel.clone());
        current_child_id = parent_rel.left_node_id.clone();

        depth += 1;
        if depth > MAX_DEPTH {
            log::warn!(
                "Max recursion depth ({}) reached for sbom_id: {}",
                MAX_DEPTH,
                sbom_id
            );
            break;
        }
    }

    log::debug!("Found {} ancestors for node", ancestors.len());
    Ok(ancestors)
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
    let mut matched_sboms = Vec::new();
    let mut visited = HashSet::new();

    for matched in rows {
        // find top level package of matched sbom
        let top_packages_of_sbom =
            find_node_ancestors(matched.sbom_id, matched.node_id, connection).await?;

        // resolve top ancestor externally linked sboms
        let mut cpes = HashSet::new();
        let mut top_ancestor_sbom = matched.sbom_id; // default

        for package in top_packages_of_sbom {
            // find_external_refs is recursive
            let external_sboms = find_external_refs(
                package.sbom_id,
                package.left_node_id,
                connection,
                &mut visited,
            )
            .await?;
            log::debug!("ancestor external sboms: {:?}", external_sboms);

            top_ancestor_sbom = external_sboms
                .last()
                .map(|a| a.sbom_id)
                .unwrap_or(matched.sbom_id);

            cpes.extend(describing_cpes(connection, top_ancestor_sbom).await?);
        }

        matched_sboms // createbuild up RankedSboms
            .extend(cpes.into_iter().map(|cpe_id| RankedSbom {
                matched_sbom_id: matched.sbom_id,
                matched_name: matched.name.clone(),
                top_ancestor_sbom,
                cpe_id,
                sbom_date: matched.published, // TODO: ensure to revisit this assumption
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::data::*;
    use futures::{StreamExt, TryStreamExt, stream};
    use rstest::rstest;
    use test_context::test_context;
    use trustify_entity::cpe;
    use trustify_test_context::{IngestionResult, TrustifyContext};

    #[test_context(TrustifyContext)]
    #[rstest]
    #[case(rpm::older(), &["cpe:/a:redhat:enterprise_linux:9.7:*:appstream:*", "cpe:/a:redhat:enterprise_linux:9:*:appstream:*"][..])]
    #[test_log::test(actix_web::test)]
    async fn describing_cpes(
        ctx: &TrustifyContext,
        #[case] sources: impl IntoIterator<Item = String>,
        #[case] expected: &[&str],
    ) -> Result<(), anyhow::Error> {
        let [product, _rpm] = ctx.ingest_documents(sources).await?.into_uuid();

        let cpes = stream::iter(super::describing_cpes(&ctx.db, product).await?)
            .then(async |cpe| cpe::Entity::find_by_id(cpe).all(&ctx.db).await)
            .try_fold(Vec::new(), |mut acc, models| async move {
                acc.extend(models.into_iter().map(|cpe| cpe.to_string()));
                Ok(acc)
            })
            .await?;

        assert_eq!(cpes.as_slice(), expected);

        Ok(())
    }
}
