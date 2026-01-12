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
use tracing::instrument;
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom, sbom_external_node, sbom_node,
    sbom_package_cpe_ref,
};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedSbom {
    pub matched_sbom_id: Uuid,
    pub matched_name: String,
    #[allow(dead_code)] // good for debugging
    #[allow(dead_code)] // good for debugging
    pub top_ancestor_sbom: Uuid,
    pub cpe_id: Uuid,
    pub sbom_date: DateTimeWithTimeZone,
    pub rank: Option<usize>,
}

/// prepare a select statement, returning [`Row`]s.
pub fn select() -> Select<sbom_node::Entity> {
    sbom_node::Entity::find()
        .distinct()
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
    _visited: &mut HashSet<Uuid>,
) -> Result<Vec<ResolvedSbom>, Error>
where
    C: ConnectionTrait + Send,
{
    // TODO: we need to fix cyclic detection
    // if !visited.insert(sbom_id) {
    //     log::warn!("Cycle detected for SBOM {}, skipping recursion.", sbom_id);
    //     return Ok(vec![]);
    // }

    let mut all_resolved_sboms = vec![];

    // execute query and handle the result safely ONCE.
    // usage: resolve_rh_external_sbom_ancestors likely returns Result<Vec<...>, Error>
    let direct_ancestors = resolve_rh_external_sbom_ancestors(sbom_id, node_id, connection).await?;

    for ancestor in direct_ancestors {
        all_resolved_sboms.push(ancestor.clone());

        let top_package_of_sbom =
            find_node_ancestors(ancestor.sbom_id, ancestor.node_id.clone(), connection).await?;

        for package in top_package_of_sbom {
            let deep_ancestors =
                find_external_refs(package.sbom_id, package.left_node_id, connection, _visited)
                    .await?;

            all_resolved_sboms.extend(deep_ancestors);
        }
    }

    Ok(all_resolved_sboms)
}

/// Retrieves the distinct list of CPE (Common Platform Enumeration) UUIDs associated with a specific SBOM,
/// specifically the "describing component" of an SBOM.
///
/// This means: all CPEs of all nodes which have the SBOM's node ID on the right side of a "describes" relationship
///
/// This function queries the `sbom_package_cpe_ref` linking table to find all CPEs tied
/// to the given `sbom_id`. It includes validation joins to ensure the SBOM exists and
/// properly contains a "Describes" relationship (indicating a valid root package structure).
///
/// # Arguments
///
/// * `connection` - The database connection used to execute the query.
/// * `sbom_id` - The UUID of the SBOM to search within.
///
/// # Returns
///
/// Returns a `Result` containing:
/// * `Vec<Uuid>`: A list of unique CPE UUIDs found in the SBOM.
/// * `Error`: If a database error occurs.
///
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

/// Retrieves lineage (ancestors) of a specific node within an SBOM graph as represented
/// in sql data (NOT in memory graph).
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

        // no parents found
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
#[instrument(skip(connection, rows), fields(rows=rows.len()))]
pub async fn resolve_sbom_cpes(
    cpe_search: bool,
    connection: &(impl ConnectionTrait + Send),
    rows: Vec<Row>,
) -> Result<Vec<RankedSbom>, Error> {
    let mut matched_sboms = Vec::new();
    let mut visited = HashSet::new();

    for matched in rows {
        // cpe search means our matched nodes are always top level sbom DESCRIBE
        if cpe_search {
            // TODO: this mess is temporary and will be refactored
            let direct_cpes = describing_cpes(connection, matched.sbom_id).await?;
            let direct_external_sboms = sbom_external_node::Entity::find()
                .filter(sbom_external_node::Column::SbomId.eq(matched.sbom_id))
                .all(connection)
                .await?;
            for direct_cpe in direct_cpes {
                for direct_external_sbom in &direct_external_sboms {
                    let direct_external_sbom_node = sbom_node::Entity::find()
                        .filter(
                            sbom_node::Column::NodeId.eq(&direct_external_sbom.external_node_ref),
                        )
                        .one(connection)
                        .await?
                        .ok_or_else(|| {
                            Error::Data("Ranked matched node has no top ancestor sbom.".to_string())
                        })?;

                    matched_sboms // create RankedSboms
                        .push(RankedSbom {
                            matched_sbom_id: matched.sbom_id,
                            matched_name: direct_external_sbom_node.name,
                            top_ancestor_sbom: direct_external_sbom_node.sbom_id,
                            cpe_id: direct_cpe,
                            sbom_date: matched.published, // TODO: ensure to revisit this assumption
                            rank: None,
                        });
                }
            }
        }

        // find top level package of matched sbom
        let top_packages_of_sbom =
            find_node_ancestors(matched.clone().sbom_id, matched.clone().node_id, connection)
                .await?;

        let external_sboms = match top_packages_of_sbom.is_empty() {
            true => {
                // if top_packages_of_sbom is empty then matched node might be the top level
                // package of the matched sbom
                resolve_rh_external_sbom_ancestors(matched.sbom_id, matched.node_id, connection)
                    .await?
            }
            false => {
                // finally we can now resolve top ancestor externally linked sboms
                // to the matched node
                let mut external_sboms = Vec::new();

                for package in top_packages_of_sbom {
                    // find_external_refs is recursive
                    external_sboms.extend(
                        find_external_refs(
                            package.sbom_id,
                            package.left_node_id,
                            connection,
                            &mut visited,
                        )
                        .await?,
                    );
                }

                external_sboms
            }
        };
        log::debug!("external_sboms {:?}", external_sboms);

        for external_sbom in external_sboms {
            let mut cpes = HashSet::new();
            cpes.extend(describing_cpes(connection, external_sbom.sbom_id).await?);
            log::debug!("Cpes: {:?}", cpes);
            matched_sboms // create RankedSboms
                .extend(cpes.into_iter().map(|cpe_id| RankedSbom {
                    matched_sbom_id: matched.sbom_id,
                    matched_name: matched.name.clone(),
                    top_ancestor_sbom: external_sbom.sbom_id,
                    cpe_id,
                    sbom_date: matched.published, // TODO: ensure to revisit this assumption
                    rank: None,
                }));
        }
    }

    Ok(matched_sboms)
}

/// Assigns a rank to SBOMs within their specific CPE groups based on creation date which
/// embodies the latest filter heuristics.
///
/// This function simulates a SQL Window Function:
/// `DENSE_RANK() OVER (PARTITION BY cpe_id ORDER BY sbom_date DESC)`.
///
/// # Logic
/// 1. **Sort**: The list is sorted primarily by `cpe_id`, `name` (to group items) and secondarily
///    by `sbom_date` in descending order (newest first).
/// 2. **Rank**: It iterates through the sorted list:
///    - **New Group**: If the `cpe_id`, `name` changes, the rank resets to 1.
///    - **Ties**: If the `sbom_date` is identical to the previous item in the same group,
///      they share the same rank.
///    - **Progression**: If the date is older, the rank increments by 1 (creating a "Dense" rank,
///      meaning no numbers are skipped after ties: 1, 1, 2).
///
/// # Arguments
/// * `items` - A mutable slice of `RankedSbom` that will be sorted and updated in-place.
pub fn apply_rank(items: &mut [RankedSbom]) {
    // group by (cpe_id, matched_name) before ordering by date.
    items.sort_by(|a, b| {
        a.cpe_id
            .cmp(&b.cpe_id) // partition: CPE
            .then(a.matched_name.cmp(&b.matched_name)) // partition: Name
            // .then(a.matched_group.cmp(&b.matched_group)) // partition: Group
            .then(b.sbom_date.cmp(&a.sbom_date)) // Ordering: Date DESC
    });

    let mut current_rank = 1;

    for i in 0..items.len() {
        // first item is always Rank 1
        if i == 0 {
            items[i].rank = Some(1);
            continue;
        }

        let prev = &items[i - 1];
        let curr = &items[i];

        // we are in the same group only if BOTH
        // the CPE and the Name match the previous item.
        let same_partition = curr.cpe_id == prev.cpe_id && curr.matched_name == prev.matched_name;
        // curr.matched_group == prev.matched_group &&
        // curr.matched_name == prev.matched_name;

        if same_partition {
            // dense rank logic
            if curr.sbom_date == prev.sbom_date {
                items[i].rank = items[i - 1].rank;
            } else {
                current_rank += 1;
                items[i].rank = Some(current_rank);
            }
        } else {
            // partition boundary detected (eg. CPE changed OR Name changed).
            // reset rank counter.
            current_rank = 1;
            items[i].rank = Some(1);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::data::*;
    use chrono::{TimeZone, Utc};
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

    /// create a simple [`RankedSbom`] for testing
    fn ranked(
        sbom: Uuid,
        name: &str,
        cpe_id: Uuid,
        date: chrono::DateTime<Utc>,
        rank: usize,
    ) -> RankedSbom {
        RankedSbom {
            matched_sbom_id: sbom,
            matched_name: name.to_string(),
            top_ancestor_sbom: Default::default(),
            cpe_id,
            sbom_date: date.into(),
            rank: Some(rank),
        }
    }

    /// create an ID for a CPE for testing
    const fn cpe(i: u8) -> Uuid {
        Uuid::new_v8([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, i])
    }

    /// create an ID for an SBOM for testing
    const fn sbom(i: u8) -> Uuid {
        Uuid::new_v8([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, i])
    }

    /// Create a timestamp based on a day, all timestamps created will only very by this day.
    ///
    /// The idea is to create timestamps for a stream of days: day 1, day 2, day x, ..
    fn utc(day: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, day, 0, 0, 0).unwrap()
    }

    /// Testing the [`super::apply_rank`] function.
    #[rstest]
    #[case::empty([])]
    #[case::one([
        ranked(sbom(1), "a", cpe(1), utc(1), 1),
    ])]
    #[case::two_later([
        ranked(sbom(1), "a", cpe(1), utc(1), 2),
        ranked(sbom(2), "a", cpe(1), utc(2), 1),
    ])]
    #[case::two_later_swapped([
        ranked(sbom(2), "a", cpe(1), utc(2), 1),
        ranked(sbom(1), "a", cpe(1), utc(1), 2),
    ])]
    #[case::two_different([
        ranked(sbom(1), "a", cpe(1), utc(1), 1),
        ranked(sbom(2), "a", cpe(2), utc(2), 1),
    ])]
    #[case::two_streams([
        ranked(sbom(1), "a", cpe(1), utc(1), 2),
        ranked(sbom(2), "a", cpe(1), utc(2), 1),
        ranked(sbom(3), "a", cpe(2), utc(1), 2),
        ranked(sbom(4), "a", cpe(2), utc(2), 1),
    ])]
    #[case::two_streams_swapped([
        ranked(sbom(1), "a", cpe(1), utc(1), 2),
        ranked(sbom(2), "a", cpe(2), utc(1), 2),
        ranked(sbom(3), "a", cpe(1), utc(2), 1),
        ranked(sbom(4), "a", cpe(2), utc(2), 1),
    ])]
    #[case::two_streams_names([
        ranked(sbom(1), "a", cpe(1), utc(1), 2),
        ranked(sbom(2), "a", cpe(1), utc(2), 1),
        ranked(sbom(3), "b", cpe(1), utc(1), 2),
        ranked(sbom(4), "b", cpe(1), utc(2), 1),
    ])]
    fn apply_rank_1(#[case] items: impl IntoIterator<Item = RankedSbom>) {
        // collect first
        let mut expected = items.into_iter().collect::<Vec<_>>();

        // create input by stripping rank
        let mut items = expected
            .iter()
            .map(|item| RankedSbom {
                rank: None,
                ..item.clone()
            })
            .collect::<Vec<_>>();

        // process

        apply_rank(&mut items);

        // validate

        let key = |a: &RankedSbom| (a.matched_sbom_id, a.matched_name.clone(), a.cpe_id, a.rank);
        items.sort_by_key(key);
        expected.sort_by_key(key);
        assert_eq!(items, expected);
    }
}
