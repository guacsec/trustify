use crate::service::load::LoadContext;
use crate::{
    Error,
    service::{ResolvedSbom, resolve_rh_external_sbom_ancestors},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, QueryFilter, QuerySelect,
    RelationTrait, Select, prelude::DateTimeWithTimeZone,
};
use sea_query::JoinType;
use std::collections::{HashMap, HashSet};
use tracing::{Instrument, instrument};
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom, sbom_external_node, sbom_node,
    sbom_node_cpe_ref,
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

/// Cached result for a single step of `find_external_refs`, storing both the resolved SBOMs
/// and the child keys to push onto the DFS stack on replay.
#[derive(Clone, Debug, Default)]
pub(super) struct CachedExternalRefs {
    pub resolved: Vec<ResolvedSbom>,
    pub children: Vec<(Uuid, String)>,
}

/// Resolves external SBOM references using iterative DFS with caching.
///
/// Walks the external-reference graph starting from (sbom_id, node_id). Each step resolves
/// direct ancestors and finds their top-level packages, which become the next DFS entries.
/// Results and children are cached per (sbom_id, node_id) so repeated calls with a shared
/// `LoadContext` replay the traversal from cache.
#[instrument(
    skip(connection, context, visited),
    fields(visited_len=visited.len()),
    err(level=tracing::Level::INFO)
)]
async fn find_external_refs<C>(
    sbom_id: Uuid,
    node_id: String,
    connection: &C,
    context: &mut LoadContext,
    visited: &mut HashSet<(Uuid, String)>,
) -> Result<Vec<ResolvedSbom>, Error>
where
    C: ConnectionTrait + Send,
{
    let mut all_resolved_sboms = Vec::new();
    let mut stack = vec![(sbom_id, node_id)];

    while let Some((sbom_id, node_id)) = stack.pop() {
        let key = (sbom_id, node_id.clone());

        if !visited.insert(key.clone()) {
            log::debug!("cycle detected for SBOM {sbom_id} / {node_id}, skipping");
            continue;
        }

        // On cache hit, replay resolved SBOMs and push cached children onto the stack
        if let Some(cached) = context.find_external_refs.get_cached(&key) {
            all_resolved_sboms.extend(cached.resolved);
            stack.extend(cached.children);
            continue;
        }

        let direct_ancestors =
            resolve_rh_external_sbom_ancestors(sbom_id, node_id, connection).await?;

        let mut children = Vec::new();
        for ancestor in &direct_ancestors {
            let top_packages = find_node_ancestors(
                ancestor.sbom_id,
                ancestor.node_id.clone(),
                connection,
                context,
            )
            .await?;

            for package in top_packages {
                children.push((package.sbom_id, package.left_node_id));
            }
        }

        stack.extend(children.iter().cloned());

        context.find_external_refs.insert(
            key,
            CachedExternalRefs {
                resolved: direct_ancestors.clone(),
                children,
            },
        );

        all_resolved_sboms.extend(direct_ancestors);
    }

    Ok(all_resolved_sboms)
}

/// Retrieves the distinct list of CPE (Common Platform Enumeration) UUIDs associated with a specific SBOM,
/// specifically the "describing component" of an SBOM.
///
/// This means: all CPEs of all nodes which have the SBOM's node ID on the right side of a "describes" relationship
///
/// This function queries the `sbom_node_cpe_ref` linking table to find all CPEs tied
/// to the given `sbom_id`. It includes validation joins to ensure the SBOM exists and
/// properly contains a "Describes" relationship (indicating a valid root package structure).
///
/// # Arguments
///
/// * `connection` - The database connection used to execute the query.
/// * `context` - Caching context to avoid redundant DB queries.
/// * `sbom_id` - The UUID of the SBOM to search within.
///
/// # Returns
///
/// Returns a `Result` containing:
/// * `Vec<Uuid>`: A list of unique CPE UUIDs found in the SBOM.
/// * `Error`: If a database error occurs.
///
#[instrument(skip(connection, context), err(level=tracing::Level::INFO))]
async fn describing_cpes(
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
    sbom_id: Uuid,
) -> Result<Vec<Uuid>, Error> {
    Ok(context
        .describing_cpes
        .get(connection, sbom_id, async |connection, sbom_id| {
            sbom_node_cpe_ref::Entity::find()
                .distinct()
                .select_only()
                .column(sbom_node_cpe_ref::Column::CpeId)
                .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom_id))
                .join(JoinType::Join, sbom_node_cpe_ref::Relation::Sbom.def())
                .join(
                    JoinType::Join,
                    sbom::Relation::PackageRelatesToPackages.def(),
                )
                .filter(
                    package_relates_to_package::Column::Relationship.eq(Relationship::Describes),
                )
                .into_tuple::<Uuid>()
                .all(connection)
                .await
        })
        .await?)
}

/// Batch-fetches describing CPEs for multiple SBOMs in a single query.
///
/// Checks the cache first and only queries the database for uncached SBOM IDs.
/// Results are inserted into the cache and returned as a map from SBOM ID to CPE IDs.
#[instrument(
    skip(connection, context, sbom_ids),
    fields(sbom_ids = sbom_ids.len()),
    err(level=tracing::Level::INFO))
]
async fn describing_cpes_batch(
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
    sbom_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Uuid>>, Error> {
    let mut result = HashMap::with_capacity(sbom_ids.len());
    let mut seen = HashSet::new();
    let mut uncached_ids = Vec::new();

    for &sbom_id in sbom_ids {
        if let Some(cpes) = context.describing_cpes.get_cached(&sbom_id) {
            result.insert(sbom_id, cpes);
        } else if seen.insert(sbom_id) {
            uncached_ids.push(sbom_id);
        }
    }

    if uncached_ids.is_empty() {
        return Ok(result);
    }

    let rows = sbom_node_cpe_ref::Entity::find()
        .distinct()
        .select_only()
        .column(sbom_node_cpe_ref::Column::SbomId)
        .column(sbom_node_cpe_ref::Column::CpeId)
        .filter(sbom_node_cpe_ref::Column::SbomId.is_in(uncached_ids.clone()))
        .join(JoinType::Join, sbom_node_cpe_ref::Relation::Sbom.def())
        .join(
            JoinType::Join,
            sbom::Relation::PackageRelatesToPackages.def(),
        )
        .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Describes))
        .into_tuple::<(Uuid, Uuid)>()
        .all(connection)
        .await?;

    let mut fetched: HashMap<_, Vec<_>> = HashMap::new();
    for (sbom_id, cpe_id) in rows {
        fetched.entry(sbom_id).or_default().push(cpe_id);
    }

    // Cache all results, including empty vecs for IDs that returned no rows
    for sbom_id in uncached_ids {
        let cpes = fetched.remove(&sbom_id).unwrap_or_default();
        context.describing_cpes.insert(sbom_id, cpes.clone());
        result.insert(sbom_id, cpes);
    }

    Ok(result)
}

/// Retrieves lineage (ancestors) of a specific node within an SBOM graph as represented
/// in sql data (NOT in memory graph).
///
/// This function performs an iterative upstream traversal starting from the `start_node_id`.
/// It walks the `package_relates_to_package` table from Child to Parent until it reaches
/// a root node (no further parents).
///
/// # Arguments
///
/// * `sbom_id` - The unique identifier of the SBOM to scope the search within.
/// * `start_node_id` - The identifier of the child node to begin the traversal from.
/// * `connection` - The database connection used to execute the queries.
/// * `context` - Caching context to avoid redundant DB queries.
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
///   currently selects *a single random* parent returned by the database and ignores others.
/// * **Cycle Protection**: Records visited nodes of the SBOM to prevent infinite loops in
///   cyclic graphs (e.g., A -> B -> A).
#[instrument(skip(connection, context), err(level=tracing::Level::INFO))]
pub async fn find_node_ancestors<C: ConnectionTrait>(
    sbom_id: Uuid,
    start_node_id: String,
    connection: &C,
    context: &mut LoadContext,
) -> Result<Vec<package_relates_to_package::Model>, DbErr> {
    let mut ancestors = Vec::new();
    let mut current_child_id = start_node_id;

    // guard to prevent infinite loops (e.g. cycles A->B->A)
    let mut visited = HashSet::new();

    let mut iterations = 0;
    loop {
        if !visited.insert(current_child_id.clone()) {
            log::warn!("recursion detected (node: {current_child_id}, sbom: {sbom_id})");
            break;
        }

        // Individual parent lookups are cached so that different starting nodes
        // sharing ancestor paths benefit from previously resolved steps.
        let parents = context
            .find_node_ancestors
            .get(
                connection,
                (sbom_id, current_child_id.clone()),
                async |connection, (sbom_id, child_id)| {
                    package_relates_to_package::Entity::find()
                        .filter(package_relates_to_package::Column::SbomId.eq(sbom_id))
                        .filter(package_relates_to_package::Column::RightNodeId.eq(&child_id))
                        .filter(
                            package_relates_to_package::Column::Relationship
                                .ne(Relationship::AncestorOf),
                        )
                        .all(connection)
                        .await
                },
            )
            .await?;

        if parents.is_empty() {
            break;
        }

        let parent_rel = &parents[0];
        ancestors.push(parent_rel.clone());
        current_child_id = parent_rel.left_node_id.clone();

        iterations += 1;
    }

    log::debug!(
        "Took {iterations} iterations, found {} ancestors for node",
        ancestors.len()
    );

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

    let mut context = LoadContext::default();

    for matched in rows {
        matched_sboms
            .extend(resolve_sbom_cpe(matched, cpe_search, connection, &mut context).await?);
    }

    log::info!("Cache stats: {context:?}");

    Ok(matched_sboms)
}

/// Resolves direct CPE matches by joining external nodes to SBOM nodes.
/// (hopefully avoiding N+1 queries).
#[instrument(skip(connection), err(level=tracing::Level::INFO))]
async fn resolve_direct_cpe_matches(
    matched: &Row,
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
) -> Result<Vec<RankedSbom>, Error> {
    let direct = describing_cpes(connection, context, matched.sbom_id);
    let direct_external = async {
        sbom_external_node::Entity::find()
            .filter(sbom_external_node::Column::SbomId.eq(matched.sbom_id))
            .all(connection)
            .instrument(tracing::info_span!("find external sboms").or_current())
            .await
            .map_err(Error::from)
    };

    let (direct_cpes, direct_external_sboms) = tokio::try_join!(direct, direct_external)?;

    if direct_external_sboms.is_empty() {
        return Ok(vec![]);
    }

    let node_ids: Vec<_> = direct_external_sboms
        .iter()
        .map(|e| e.external_node_ref.clone())
        .collect();

    let nodes = sbom_node::Entity::find()
        .filter(sbom_node::Column::NodeId.is_in(node_ids))
        .all(connection)
        .instrument(tracing::info_span!("lookup nodes").or_current())
        .await
        .map_err(Error::from)?;

    let node_map: HashMap<_, _> = nodes.into_iter().map(|n| (n.node_id.clone(), n)).collect();

    let mut matched_sboms = Vec::with_capacity(direct_cpes.len() * direct_external_sboms.len());

    for direct_cpe in direct_cpes {
        for ext_sbom in &direct_external_sboms {
            let node = node_map.get(&ext_sbom.external_node_ref).ok_or_else(|| {
                Error::Data("Ranked matched node has no top ancestor sbom.".to_string())
            })?;

            matched_sboms.push(RankedSbom {
                matched_sbom_id: matched.sbom_id,
                matched_name: node.name.clone(),
                top_ancestor_sbom: node.sbom_id,
                cpe_id: direct_cpe,
                sbom_date: matched.published,
                rank: None,
            });
        }
    }

    Ok(matched_sboms)
}

/// Finds external SBOMs that are ancestors of the matched node.
#[instrument(skip(connection), err(level=tracing::Level::INFO))]
async fn resolve_ancestor_external_sboms(
    matched: &Row,
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
) -> Result<Vec<ResolvedSbom>, Error> {
    let top_packages = find_node_ancestors(
        matched.sbom_id,
        matched.node_id.clone(),
        connection,
        context,
    )
    .await?;

    log::debug!("Top packages found? {:?}", top_packages.is_empty());

    if top_packages.is_empty() {
        // the matched node IS the top-level package
        resolve_rh_external_sbom_ancestors(matched.sbom_id, matched.node_id.clone(), connection)
            .await
    } else {
        // the matched node is nested; resolve ancestors recursively
        let mut external_sboms = Vec::new();
        let mut visited = HashSet::new(); // Reused allocation

        for package in top_packages {
            external_sboms.extend(
                find_external_refs(
                    package.sbom_id,
                    package.left_node_id,
                    connection,
                    context,
                    &mut visited,
                )
                .await?,
            );
        }
        Ok(external_sboms)
    }
}

/// Expands a list of External SBOMs into RankedSboms by fetching their CPEs in a single batch.
#[instrument(
    skip(external_sboms, connection),
    fields(num_external_sboms = external_sboms.len()),
    err(level=tracing::Level::INFO))
]
async fn enrich_external_sboms(
    matched: &Row,
    external_sboms: Vec<ResolvedSbom>,
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
) -> Result<Vec<RankedSbom>, Error> {
    let sbom_ids: Vec<Uuid> = external_sboms.iter().map(|s| s.sbom_id).collect();
    let cpes_by_sbom = describing_cpes_batch(connection, context, &sbom_ids).await?;

    let mut results = Vec::new();

    for external_sbom in &external_sboms {
        let cpes = cpes_by_sbom
            .get(&external_sbom.sbom_id)
            .cloned()
            .unwrap_or_default();

        log::debug!(
            "{:?}/{} -> CPEs: {:?}",
            external_sbom.sbom_id,
            external_sbom.node_id,
            cpes
        );

        results.extend(cpes.into_iter().map(|cpe_id| RankedSbom {
            matched_sbom_id: matched.sbom_id,
            matched_name: matched.name.clone(),
            top_ancestor_sbom: external_sbom.sbom_id,
            cpe_id,
            sbom_date: matched.published,
            rank: None,
        }));
    }

    Ok(results)
}

/// Resolve CPEs for matched SBOMs.
///
/// The CPEs of an SBOM are the CPEs of the describing component.
///
/// ## Input
///
/// * `matched`: single matched row of the initial search
///
/// ## Output
///
/// * A Vec of nodes matching, filled with their CPE.
///
#[instrument(skip(connection, context), err(level=tracing::Level::INFO))]
async fn resolve_sbom_cpe(
    matched: Row,
    cpe_search: bool,
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
) -> Result<Vec<RankedSbom>, Error> {
    let mut results = Vec::new();

    if cpe_search {
        let direct_matches = resolve_direct_cpe_matches(&matched, connection, context).await?;
        results.extend(direct_matches);
    }

    // find external SBOMs linked to ancestors
    let external_sboms = resolve_ancestor_external_sboms(&matched, connection, context).await?;
    log::debug!("external_sboms {:?}", external_sboms.len());

    // expand external SBOMs into RankedSboms with CPEs
    let ancestor_matches =
        enrich_external_sboms(&matched, external_sboms, connection, context).await?;
    results.extend(ancestor_matches);

    Ok(results)
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
    use std::time::Duration;
    use test_context::test_context;
    use tokio::time::timeout;
    use trustify_entity::cpe;
    use trustify_test_context::{IngestionResult, TrustifyContext};

    /// Ensure that [`super::find_node_ancestors`] doesn't do infinite runs when having node cycles.
    #[test_context(TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn find_node_ancestors(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let [id] = ctx
            .ingest_documents(["cyclonedx/loop.json"])
            .await?
            .into_uuid();

        let result =
            super::find_node_ancestors(id, "C".into(), &ctx.db, &mut Default::default()).await?;
        let result = result
            .iter()
            .map(|rel| (rel.left_node_id.as_str(), rel.right_node_id.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(result, [("B", "C"), ("A", "B"), ("C", "A")]);

        Ok(())
    }

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

        let cpes =
            stream::iter(super::describing_cpes(&ctx.db, &mut Default::default(), product).await?)
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

    /// Ensure that [`find_external_refs`] terminates when two SBOMs reference each other
    /// cyclically via shared package checksums.
    #[test_context(TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn find_external_refs_cycle(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let [id_a, _id_b] = ctx
            .ingest_documents(["spdx/cycle/ext-a.json", "spdx/cycle/ext-b.json"])
            .await?
            .into_uuid();

        let mut visited = HashSet::new();
        let mut context = LoadContext::default();

        // no native test timeout in Rust, using tokio's timeout as a deadlock guard

        let mut result = timeout(
            Duration::from_secs(10),
            find_external_refs(
                id_a,
                "SPDXRef-Root-A".into(),
                &ctx.db,
                &mut context,
                &mut visited,
            ),
        )
        .await
        .expect("find_external_refs should not loop infinitely")?;

        log::info!("resolved external SBOMs: {result:?}");

        // assert

        result.sort();

        assert_eq!(
            result,
            vec![
                ResolvedSbom {
                    sbom_id: id_a,
                    node_id: "SPDXRef-Leaf-A".into(),
                },
                ResolvedSbom {
                    sbom_id: _id_b,
                    node_id: "SPDXRef-Leaf-B".into(),
                },
            ]
        );

        Ok(())
    }
}
