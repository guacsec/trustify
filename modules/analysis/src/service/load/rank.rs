use crate::{
    Error,
    service::{
        ResolvedSbom, resolve_rh_external_sbom_ancestors,
        resolve_rh_external_sbom_ancestors_batch,
    },
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityTrait, FromQueryResult, QueryFilter,
    QuerySelect, RelationTrait, Select, Statement, prelude::DateTimeWithTimeZone,
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
    #[allow(dead_code)] // good for debugging
    pub top_ancestor_sbom: Uuid,
    pub cpe_id: Uuid,
    pub sbom_date: DateTimeWithTimeZone,
    pub rank: Option<usize>,
}

/// Helper for deserializing recursive CTE results into `package_relates_to_package::Model`.
#[derive(Debug, Clone, FromQueryResult)]
struct AncestorRow {
    sbom_id: Uuid,
    left_node_id: String,
    relationship: Relationship,
    right_node_id: String,
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

/// Resolves external SBOM references starting from a single node.
/// Delegates to [`find_external_refs_bfs`] for the actual traversal.
#[instrument(skip(connection, visited), fields(visited_len=visited.len()), err(level = tracing::Level::INFO))]
async fn find_external_refs<C>(
    sbom_id: Uuid,
    node_id: String,
    connection: &C,
    visited: &mut HashSet<(Uuid, String)>,
) -> Result<Vec<ResolvedSbom>, Error>
where
    C: ConnectionTrait + Send,
{
    find_external_refs_bfs(vec![(sbom_id, node_id)], connection, visited).await
}

/// Resolves external SBOM references using iterative BFS with batch queries per level.
///
/// Accepts multiple starting `(sbom_id, node_id)` pairs as the initial frontier.
/// Each BFS level does 3 queries (batch external resolution + batch ancestor CTE),
/// regardless of how many nodes are in the frontier.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
async fn find_external_refs_bfs<C>(
    initial_frontier: Vec<(Uuid, String)>,
    connection: &C,
    visited: &mut HashSet<(Uuid, String)>,
) -> Result<Vec<ResolvedSbom>, Error>
where
    C: ConnectionTrait + Send,
{
    let mut all_resolved = Vec::new();
    let mut frontier = initial_frontier;

    while !frontier.is_empty() {
        frontier.retain(|(sbom_id, node_id)| visited.insert((*sbom_id, node_id.clone())));
        if frontier.is_empty() {
            break;
        }

        let resolved_map =
            resolve_rh_external_sbom_ancestors_batch(&frontier, connection).await?;

        let mut ancestor_inputs = Vec::new();
        for ancestors in resolved_map.values() {
            for ancestor in ancestors {
                all_resolved.push(ancestor.clone());
                ancestor_inputs.push((ancestor.sbom_id, ancestor.node_id.clone()));
            }
        }

        if ancestor_inputs.is_empty() {
            break;
        }

        let ancestor_chains =
            find_node_ancestors_batch(&ancestor_inputs, connection).await?;

        let mut next_frontier = Vec::new();
        for chain in ancestor_chains.values() {
            for rel in chain {
                next_frontier.push((rel.sbom_id, rel.left_node_id.clone()));
            }
        }

        frontier = next_frontier;
    }

    Ok(all_resolved)
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
/// * `sbom_id` - The UUID of the SBOM to search within.
///
/// # Returns
///
/// Returns a `Result` containing:
/// * `Vec<Uuid>`: A list of unique CPE UUIDs found in the SBOM.
/// * `Error`: If a database error occurs.
///
#[instrument(skip(connection), err(level=tracing::Level::INFO))]
async fn describing_cpes(
    connection: &(impl ConnectionTrait + Send),
    sbom_id: Uuid,
) -> Result<Vec<Uuid>, Error> {
    Ok(sbom_node_cpe_ref::Entity::find()
        .distinct()
        .select_only()
        .column(sbom_node_cpe_ref::Column::CpeId)
        .filter(sbom_node_cpe_ref::Column::SbomId.eq(sbom_id))
        .join(JoinType::Join, sbom_node_cpe_ref::Relation::Sbom.def())
        .join(
            JoinType::Join,
            sbom::Relation::PackageRelatesToPackages.def(),
        )
        .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Describes))
        .into_tuple::<Uuid>()
        .all(connection)
        .await?)
}

/// Batch version of [`describing_cpes`] — fetches CPE UUIDs for multiple SBOMs in a single query.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
async fn describing_cpes_batch(
    connection: &(impl ConnectionTrait + Send),
    sbom_ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<Uuid>>, Error> {
    if sbom_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sbom_node_cpe_ref::Entity::find()
        .distinct()
        .select_only()
        .column(sbom_node_cpe_ref::Column::SbomId)
        .column(sbom_node_cpe_ref::Column::CpeId)
        .filter(sbom_node_cpe_ref::Column::SbomId.is_in(sbom_ids.to_vec()))
        .join(JoinType::Join, sbom_node_cpe_ref::Relation::Sbom.def())
        .join(
            JoinType::Join,
            sbom::Relation::PackageRelatesToPackages.def(),
        )
        .filter(package_relates_to_package::Column::Relationship.eq(Relationship::Describes))
        .into_tuple::<(Uuid, Uuid)>()
        .all(connection)
        .await?;

    let mut result: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (sbom_id, cpe_id) in rows {
        result.entry(sbom_id).or_default().push(cpe_id);
    }

    Ok(result)
}

/// Retrieves lineage (ancestors) of a specific node within an SBOM graph using a
/// recursive CTE instead of iterative per-level queries.
///
/// Walks the `package_relates_to_package` table from Child to Parent until it reaches
/// a root node (no further parents). Cycle detection via a visited-node array in the CTE.
///
/// # Single Path Traversal
///
/// If a node has multiple parents (DAG), one parent per level is selected (via `LIMIT 1`
/// in the lateral join).
#[instrument(skip(connection), err(level = tracing::Level::INFO))]
pub async fn find_node_ancestors<C: ConnectionTrait>(
    sbom_id: Uuid,
    start_node_id: String,
    connection: &C,
) -> Result<Vec<package_relates_to_package::Model>, DbErr> {
    // AncestorOf = 9 (integer value from DeriveActiveEnum)
    const ANCESTOR_OF: i32 = 9;

    let sql = r#"
WITH RECURSIVE ancestors AS (
    SELECT sbom_id, left_node_id, relationship, right_node_id,
           ARRAY[$2::text] AS visited
    FROM (
        SELECT * FROM package_relates_to_package
        WHERE sbom_id = $1 AND right_node_id = $2 AND relationship != $3
        LIMIT 1
    ) anchor
    UNION ALL
    SELECT p.sbom_id, p.left_node_id, p.relationship, p.right_node_id,
           a.visited || a.left_node_id::text
    FROM ancestors a
    JOIN LATERAL (
        SELECT * FROM package_relates_to_package
        WHERE sbom_id = a.sbom_id AND right_node_id = a.left_node_id
          AND relationship != $3
        LIMIT 1
    ) p ON true
    WHERE NOT (a.left_node_id = ANY(a.visited))
)
SELECT sbom_id, left_node_id, relationship::int4, right_node_id FROM ancestors
"#;

    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        sql,
        [sbom_id.into(), start_node_id.into(), ANCESTOR_OF.into()],
    );

    let rows = AncestorRow::find_by_statement(stmt).all(connection).await?;

        let ancestors = rows
        .into_iter()
        .map(|r| package_relates_to_package::Model {
            sbom_id: r.sbom_id,
            left_node_id: r.left_node_id,
            relationship: r.relationship,
            right_node_id: r.right_node_id,
        })
        .collect::<Vec<_>>();

    tracing::debug!("Found {} ancestors for node", ancestors.len());
    Ok(ancestors)
}

/// Batch version of [`find_node_ancestors`] — runs a single recursive CTE for all
/// `(sbom_id, node_id)` pairs, returning ancestor chains grouped by input pair.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
async fn find_node_ancestors_batch<C: ConnectionTrait>(
    inputs: &[(Uuid, String)],
    connection: &C,
) -> Result<HashMap<(Uuid, String), Vec<package_relates_to_package::Model>>, DbErr> {
    if inputs.is_empty() {
        return Ok(HashMap::new());
    }

    const ANCESTOR_OF: i32 = 9;

    let mut sql_parts = Vec::with_capacity(inputs.len());
    let mut params: Vec<sea_orm::Value> = Vec::with_capacity(inputs.len() * 2 + 1);

    for (i, (sbom_id, node_id)) in inputs.iter().enumerate() {
        let idx = i * 2;
        sql_parts.push(format!("(${}::uuid, ${}::text)", idx + 1, idx + 2));
        params.push((*sbom_id).into());
        params.push(node_id.clone().into());
    }

    let ancestor_of_param_idx = params.len() + 1;
    params.push(ANCESTOR_OF.into());

    let values_clause = sql_parts.join(", ");
    let sql = format!(
        r#"
WITH RECURSIVE
input_nodes(root_sbom_id, root_node_id) AS (VALUES {values_clause}),
ancestors AS (
    SELECT i.root_sbom_id, i.root_node_id,
           p.sbom_id, p.left_node_id, p.relationship, p.right_node_id,
           ARRAY[i.root_node_id::text] AS visited
    FROM input_nodes i
    JOIN LATERAL (
        SELECT * FROM package_relates_to_package
        WHERE sbom_id = i.root_sbom_id AND right_node_id = i.root_node_id
          AND relationship != ${ancestor_of_param_idx}
        LIMIT 1
    ) p ON true
    UNION ALL
    SELECT a.root_sbom_id, a.root_node_id,
           p.sbom_id, p.left_node_id, p.relationship, p.right_node_id,
           a.visited || a.left_node_id::text
    FROM ancestors a
    JOIN LATERAL (
        SELECT * FROM package_relates_to_package
        WHERE sbom_id = a.sbom_id AND right_node_id = a.left_node_id
          AND relationship != ${ancestor_of_param_idx}
        LIMIT 1
    ) p ON true
    WHERE NOT (a.left_node_id = ANY(a.visited))
)
SELECT root_sbom_id, root_node_id,
       sbom_id, left_node_id, relationship::int4, right_node_id
FROM ancestors
"#
    );

    let stmt = Statement::from_sql_and_values(DatabaseBackend::Postgres, &sql, params);

    #[derive(Debug, FromQueryResult)]
    struct BatchAncestorRow {
        root_sbom_id: Uuid,
        root_node_id: String,
        sbom_id: Uuid,
        left_node_id: String,
        relationship: Relationship,
        right_node_id: String,
    }

    let rows = BatchAncestorRow::find_by_statement(stmt)
        .all(connection)
        .await?;

    let mut result: HashMap<(Uuid, String), Vec<package_relates_to_package::Model>> =
        HashMap::new();
    for r in rows {
        result
            .entry((r.root_sbom_id, r.root_node_id))
            .or_default()
            .push(package_relates_to_package::Model {
                sbom_id: r.sbom_id,
                left_node_id: r.left_node_id,
                relationship: r.relationship,
                right_node_id: r.right_node_id,
            });
    }

    Ok(result)
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

    for matched in rows {
        matched_sboms.extend(resolve_sbom_cpe(matched, cpe_search, connection).await?);
    }

    Ok(matched_sboms)
}

/// Resolves direct CPE matches by joining external nodes to SBOM nodes.
/// (hopefully avoiding N+1 queries).
#[instrument(skip(connection), err(level=tracing::Level::INFO))]
async fn resolve_direct_cpe_matches(
    matched: &Row,
    connection: &(impl ConnectionTrait + Send),
) -> Result<Vec<RankedSbom>, Error> {
    let direct = describing_cpes(connection, matched.sbom_id);
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
) -> Result<Vec<ResolvedSbom>, Error> {
    let top_packages =
        find_node_ancestors(matched.sbom_id, matched.node_id.clone(), connection).await?;

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
                    &mut visited,
                )
                .await?,
            );
        }
        Ok(external_sboms)
    }
}

/// Expands a list of External SBOMs into RankedSboms by fetching their CPEs in batch.
#[instrument(skip(external_sboms, connection), err(level = tracing::Level::INFO))]
async fn enrich_external_sboms(
    matched: &Row,
    external_sboms: Vec<ResolvedSbom>,
    connection: &(impl ConnectionTrait + Send),
) -> Result<Vec<RankedSbom>, Error> {
    let sbom_ids: Vec<Uuid> = external_sboms.iter().map(|e| e.sbom_id).collect();
    let cpes_map = describing_cpes_batch(connection, &sbom_ids).await?;

    let mut results = Vec::new();
    for external_sbom in external_sboms {
        if let Some(cpes) = cpes_map.get(&external_sbom.sbom_id) {
            results.extend(cpes.iter().map(|&cpe_id| RankedSbom {
                matched_sbom_id: matched.sbom_id,
                matched_name: matched.name.clone(),
                top_ancestor_sbom: external_sbom.sbom_id,
                cpe_id,
                sbom_date: matched.published,
                rank: None,
            }));
        }
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
#[instrument(skip(connection), err(level=tracing::Level::INFO))]
async fn resolve_sbom_cpe(
    matched: Row,
    cpe_search: bool,
    connection: &(impl ConnectionTrait + Send),
) -> Result<Vec<RankedSbom>, Error> {
    let mut results = Vec::new();

    if cpe_search {
        let direct_matches = resolve_direct_cpe_matches(&matched, connection).await?;
        results.extend(direct_matches);
    }

    // find external SBOMs linked to ancestors
    let external_sboms = resolve_ancestor_external_sboms(&matched, connection).await?;
    log::debug!("external_sboms {:?}", external_sboms);

    // expand external SBOMs into RankedSboms with CPEs
    let ancestor_matches = enrich_external_sboms(&matched, external_sboms, connection).await?;
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

        let result = super::find_node_ancestors(id, "C".into(), &ctx.db).await?;
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

        // no native test timeout in Rust, using tokio's timeout as a deadlock guard

        let mut result = timeout(
            Duration::from_secs(10),
            find_external_refs(id_a, "SPDXRef-Root-A".into(), &ctx.db, &mut visited),
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

    /// Verify that [`find_node_ancestors_batch`] produces the same results as calling
    /// [`find_node_ancestors`] individually for each input.
    #[test_context(TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn find_node_ancestors_batch_matches_individual(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let [id] = ctx
            .ingest_documents(["cyclonedx/loop.json"])
            .await?
            .into_uuid();

        // Given: individual calls for nodes C and A
        let individual_c = super::find_node_ancestors(id, "C".into(), &ctx.db).await?;
        let individual_a = super::find_node_ancestors(id, "A".into(), &ctx.db).await?;

        // When: batch call with both inputs
        let batch_result = super::find_node_ancestors_batch(
            &[(id, "C".into()), (id, "A".into())],
            &ctx.db,
        )
        .await?;

        // Then: batch results match individual calls
        let to_pairs = |rels: &[package_relates_to_package::Model]| -> Vec<(String, String)> {
            rels.iter()
                .map(|r| (r.left_node_id.clone(), r.right_node_id.clone()))
                .collect()
        };

        assert_eq!(
            to_pairs(batch_result.get(&(id, "C".into())).unwrap_or(&vec![])),
            to_pairs(&individual_c),
        );
        assert_eq!(
            to_pairs(batch_result.get(&(id, "A".into())).unwrap_or(&vec![])),
            to_pairs(&individual_a),
        );

        Ok(())
    }

    /// Verify that [`resolve_rh_external_sbom_ancestors_batch`] produces the same results
    /// as calling [`resolve_rh_external_sbom_ancestors`] individually for each input.
    #[test_context(TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn resolve_rh_external_sbom_ancestors_batch_matches_individual(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let [id_a, id_b] = ctx
            .ingest_documents(["spdx/cycle/ext-a.json", "spdx/cycle/ext-b.json"])
            .await?
            .into_uuid();

        // Given: individual calls
        let mut individual_a =
            resolve_rh_external_sbom_ancestors(id_a, "SPDXRef-Root-A".into(), &ctx.db).await?;
        let mut individual_b =
            resolve_rh_external_sbom_ancestors(id_b, "SPDXRef-Root-B".into(), &ctx.db).await?;

        // When: batch call with both inputs
        let batch_result = resolve_rh_external_sbom_ancestors_batch(
            &[
                (id_a, "SPDXRef-Root-A".into()),
                (id_b, "SPDXRef-Root-B".into()),
            ],
            &ctx.db,
        )
        .await?;

        // Then: batch results match individual calls (sort for deterministic comparison)
        let mut batch_a = batch_result
            .get(&(id_a, "SPDXRef-Root-A".into()))
            .cloned()
            .unwrap_or_default();
        let mut batch_b = batch_result
            .get(&(id_b, "SPDXRef-Root-B".into()))
            .cloned()
            .unwrap_or_default();

        batch_a.sort();
        batch_b.sort();
        individual_a.sort();
        individual_b.sort();

        assert_eq!(batch_a, individual_a);
        assert_eq!(batch_b, individual_b);

        Ok(())
    }
}
