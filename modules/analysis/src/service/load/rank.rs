use crate::service::load::LoadContext;
use crate::{
    Error,
    service::{ResolvedSbom, resolve_rh_external_sbom_ancestors},
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityTrait, FromQueryResult, JoinType,
    QueryFilter, QuerySelect, RelationTrait, Select, Statement, prelude::DateTimeWithTimeZone,
};
use sea_query::Expr;
use std::collections::{HashMap, HashSet};
use tracing::{Instrument, instrument};
#[cfg(test)]
use trustify_entity::sbom_describing_cpe;
use trustify_entity::{
    package_relates_to_package, relationship::Relationship, sbom, sbom_external_node, sbom_node,
    sbom_node_checksum,
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

/// Prepare a select statement, returning [`Row`]s.
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

// ─── Ancestor walking ───────────────────────────────────────────────

/// Retrieves lineage (ancestors) of a specific node within an SBOM
/// graph using a single recursive CTE query instead of iterative DB
/// round-trips.
///
/// Walks `package_relates_to_package` from child to parent
/// (right_node_id -> left_node_id), excluding `AncestorOf`
/// relationships. The CTE handles cycle detection via a `visited`
/// path array, capped at depth 100.
///
/// Results are cached in `context.find_node_ancestors`.
#[instrument(skip(connection, context), err(level=tracing::Level::INFO))]
pub async fn find_node_ancestors<C: ConnectionTrait>(
    sbom_id: Uuid,
    start_node_id: String,
    connection: &C,
    context: &mut LoadContext,
) -> Result<Vec<package_relates_to_package::Model>, DbErr> {
    let key = (sbom_id, start_node_id.clone());

    if let Some(cached) = context.find_node_ancestors.get_cached(&key) {
        return Ok(cached);
    }

    let ancestor_of_value = 9i32;

    let sql = r#"
WITH RECURSIVE ancestors AS (
    SELECT
        p.sbom_id,
        p.left_node_id,
        p.relationship,
        p.right_node_id,
        1 AS depth,
        ARRAY[p.right_node_id] AS visited
    FROM package_relates_to_package p
    WHERE p.sbom_id = $1
      AND p.right_node_id = $2
      AND p.relationship != $3

    UNION ALL

    SELECT
        p.sbom_id,
        p.left_node_id,
        p.relationship,
        p.right_node_id,
        a.depth + 1,
        a.visited || p.right_node_id
    FROM package_relates_to_package p
    JOIN ancestors a ON p.sbom_id = a.sbom_id
        AND p.right_node_id = a.left_node_id
        AND p.relationship != $3
    WHERE a.depth < 100
      AND NOT (p.right_node_id = ANY(a.visited))
)
SELECT DISTINCT ON (depth)
    sbom_id,
    left_node_id,
    relationship,
    right_node_id
FROM ancestors
ORDER BY depth
"#;

    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        sql,
        [
            sbom_id.into(),
            start_node_id.into(),
            ancestor_of_value.into(),
        ],
    );

    let rows = package_relates_to_package::Entity::find()
        .from_raw_sql(stmt)
        .all(connection)
        .await?;

    log::debug!("Found {} ancestors for node", rows.len());

    context.find_node_ancestors.insert(key, rows.clone());

    Ok(rows)
}

/// Result row for the multi-start ancestor CTE.
#[derive(Debug, FromQueryResult)]
struct AncestorRow {
    /// Index into the input array (which start-point produced this)
    start_idx: i32,
    sbom_id: Uuid,
    left_node_id: String,
    relationship: Relationship,
    right_node_id: String,
}

/// Batch version of [`find_node_ancestors`]: walks ancestors for every
/// `(sbom_id, node_id)` pair in a single recursive CTE by passing the
/// start points through an `UNNEST` values list.
///
/// Checks `context.find_node_ancestors` cache first; only queries
/// uncached pairs. Results are stored back into the cache.
#[instrument(
    skip(connection, context, pairs),
    fields(count = pairs.len()),
    err(level = tracing::Level::INFO)
)]
async fn batch_find_ancestors<C: ConnectionTrait>(
    connection: &C,
    context: &mut LoadContext,
    pairs: &[(Uuid, String)],
) -> Result<HashMap<usize, Vec<package_relates_to_package::Model>>, DbErr> {
    if pairs.is_empty() {
        return Ok(HashMap::new());
    }

    let mut result = HashMap::new();
    let mut uncached_indices = Vec::new();

    for (idx, pair) in pairs.iter().enumerate() {
        if let Some(cached) = context.find_node_ancestors.get_cached(pair) {
            result.insert(idx, cached);
        } else {
            uncached_indices.push(idx);
        }
    }

    if uncached_indices.is_empty() {
        return Ok(result);
    }

    let ancestor_of_value = 9i32;

    // Build parallel arrays for UNNEST, only for uncached pairs
    let uncached_sbom_ids: Vec<_> = uncached_indices.iter().map(|&i| pairs[i].0).collect();
    let uncached_node_ids: Vec<_> = uncached_indices
        .iter()
        .map(|&i| pairs[i].1.clone())
        .collect();

    let sql = r#"
WITH RECURSIVE
start_points AS (
    SELECT
        row_number() OVER () - 1 AS idx,
        s AS sbom_id,
        n AS node_id
    FROM UNNEST($1::uuid[], $2::text[]) AS t(s, n)
),
ancestors AS (
    SELECT
        sp.idx::int4 AS start_idx,
        p.sbom_id,
        p.left_node_id,
        p.relationship,
        p.right_node_id,
        1 AS depth,
        ARRAY[p.right_node_id] AS visited
    FROM start_points sp
    JOIN package_relates_to_package p
        ON p.sbom_id = sp.sbom_id
       AND p.right_node_id = sp.node_id
       AND p.relationship != $3

    UNION ALL

    SELECT
        a.start_idx,
        p.sbom_id,
        p.left_node_id,
        p.relationship,
        p.right_node_id,
        a.depth + 1,
        a.visited || p.right_node_id
    FROM package_relates_to_package p
    JOIN ancestors a
        ON p.sbom_id = a.sbom_id
       AND p.right_node_id = a.left_node_id
       AND p.relationship != $3
    WHERE a.depth < 100
      AND NOT (p.right_node_id = ANY(a.visited))
)
SELECT DISTINCT ON (start_idx, depth)
    start_idx,
    sbom_id,
    left_node_id,
    relationship,
    right_node_id
FROM ancestors
ORDER BY start_idx, depth
"#;

    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        sql,
        [
            uncached_sbom_ids.into(),
            uncached_node_ids.into(),
            ancestor_of_value.into(),
        ],
    );

    let rows = AncestorRow::find_by_statement(stmt).all(connection).await?;

    // Group by the local uncached index
    let mut by_local_idx: HashMap<usize, Vec<_>> = HashMap::new();
    for row in rows {
        let local_idx = row.start_idx as usize;
        by_local_idx
            .entry(local_idx)
            .or_default()
            .push(package_relates_to_package::Model {
                sbom_id: row.sbom_id,
                left_node_id: row.left_node_id,
                relationship: row.relationship,
                right_node_id: row.right_node_id,
            });
    }

    // Map local uncached indices back to original indices and populate cache
    for (local_idx, &original_idx) in uncached_indices.iter().enumerate() {
        let chain = by_local_idx.remove(&local_idx).unwrap_or_default();
        context
            .find_node_ancestors
            .insert(pairs[original_idx].clone(), chain.clone());
        result.insert(original_idx, chain);
    }

    log::debug!(
        "batch_find_ancestors: {} inputs ({} uncached) -> {} total ancestor rows",
        pairs.len(),
        uncached_indices.len(),
        result.values().map(Vec::len).sum::<usize>()
    );
    Ok(result)
}

// ─── Batch checksum resolution ──────────────────────────────────────

/// Batch-resolves checksum-based external SBOM ancestors for multiple
/// `(sbom_id, node_id)` pairs in two queries instead of 2*N.
///
/// Returns a map from input `(sbom_id, node_id)` to the resolved
/// external SBOMs found via matching checksums.
#[instrument(
    skip(connection, pairs),
    fields(count = pairs.len()),
    err(level = tracing::Level::INFO)
)]
async fn batch_resolve_rh_external_sbom_ancestors(
    connection: &(impl ConnectionTrait + Send),
    pairs: &[(Uuid, String)],
) -> Result<HashMap<(Uuid, String), Vec<ResolvedSbom>>, Error> {
    if pairs.is_empty() {
        return Ok(HashMap::new());
    }

    // Step 1: Fetch checksums for all requested (sbom_id, node_id)
    // using UNNEST arrays to avoid deeply nested Condition trees
    // that overflow sea_query's recursive serializer.
    let sbom_ids_arr: Vec<_> = pairs.iter().map(|(sid, _)| *sid).collect();
    let node_ids_arr: Vec<_> = pairs.iter().map(|(_, nid)| nid.clone()).collect();

    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        r#"
SELECT snc.sbom_id, snc.node_id, snc.type, snc.value
FROM sbom_node_checksum snc
INNER JOIN UNNEST($1::uuid[], $2::text[]) AS t(sid, nid)
  ON snc.sbom_id = t.sid AND snc.node_id = t.nid
"#,
        [sbom_ids_arr.into(), node_ids_arr.into()],
    );

    let checksums = sbom_node_checksum::Model::find_by_statement(stmt)
        .all(connection)
        .instrument(tracing::info_span!("batch checksum lookup").or_current())
        .await?;

    if checksums.is_empty() {
        return Ok(HashMap::new());
    }

    // Index: checksum value -> source (sbom_id, node_id) pairs
    let mut value_to_sources: HashMap<_, Vec<_>> = HashMap::new();
    let mut source_sbom_ids = HashSet::new();
    for ck in &checksums {
        value_to_sources
            .entry(ck.value.clone())
            .or_default()
            .push((ck.sbom_id, ck.node_id.clone()));
        source_sbom_ids.insert(ck.sbom_id);
    }

    // Step 2: Find all other nodes sharing these checksum values,
    // with CPE IDs aggregated per (sbom_id, node_id) via array_agg
    let checksum_values: Vec<_> = value_to_sources.keys().cloned().collect();

    #[derive(Debug, FromQueryResult)]
    struct ChecksumWithValueAndCpes {
        sbom_id: Uuid,
        node_id: String,
        value: String,
        cpe_ids: Vec<Uuid>,
    }

    let rows = sbom_node_checksum::Entity::find()
        .select_only()
        .column(sbom_node_checksum::Column::SbomId)
        .column(sbom_node_checksum::Column::NodeId)
        .column(sbom_node_checksum::Column::Value)
        .column_as(
            Expr::cust(r#"COALESCE(array_agg("sbom_describing_cpe"."cpe_id") FILTER (WHERE "sbom_describing_cpe"."cpe_id" IS NOT NULL), ARRAY[]::uuid[])"#),
            "cpe_ids",
        )
        .join(
            JoinType::LeftJoin,
            sbom_node_checksum::Relation::DescribingCpe.def(),
        )
        .filter(sbom_node_checksum::Column::Value.is_in(checksum_values))
        .filter(
            sbom_node_checksum::Column::SbomId
                .is_not_in(source_sbom_ids.into_iter().collect::<Vec<_>>()),
        )
        .group_by(sbom_node_checksum::Column::SbomId)
        .group_by(sbom_node_checksum::Column::NodeId)
        .group_by(sbom_node_checksum::Column::Value)
        .into_model::<ChecksumWithValueAndCpes>()
        .all(connection)
        .instrument(tracing::info_span!("batch checksum reverse lookup with cpes").or_current())
        .await?;

    if rows.is_empty() {
        return Ok(HashMap::new());
    }

    let mut result: HashMap<_, Vec<_>> = HashMap::new();
    for row in rows {
        let Some(sources) = value_to_sources.get(&row.value) else {
            continue;
        };
        for source in sources {
            result
                .entry(source.clone())
                .or_default()
                .push(ResolvedSbom {
                    sbom_id: row.sbom_id,
                    node_id: row.node_id.clone(),
                    cpe_ids: row.cpe_ids.clone(),
                });
        }
    }

    Ok(result)
}

// ─── External-ref DFS (recursive, for deeper levels) ────────────────

/// Resolves external SBOM references via iterative DFS.
///
/// Walks cross-SBOM links discovered through checksum matching,
/// using an explicit stack instead of recursion.
/// Uses `context.find_external_refs` cache to avoid redundant traversals.
#[instrument(
    skip(connection, context, visited),
    fields(visited_len = visited.len()),
    err(level = tracing::Level::INFO)
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
    let mut all_resolved = vec![];
    let mut stack = vec![(sbom_id, node_id)];

    while let Some((current_sbom, current_node)) = stack.pop() {
        let key = (current_sbom, current_node.clone());

        if !visited.insert(key.clone()) {
            continue;
        }

        if let Some(cached) = context.find_external_refs.get_cached(&key) {
            all_resolved.extend(cached.resolved.clone());
            stack.extend(cached.children);
            continue;
        }

        let direct_ancestors =
            resolve_rh_external_sbom_ancestors(current_sbom, current_node, connection).await?;

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
                let child = (package.sbom_id, package.left_node_id);
                children.push(child.clone());
                stack.push(child);
            }
        }

        context.find_external_refs.insert(
            key,
            CachedExternalRefs {
                resolved: direct_ancestors.clone(),
                children,
            },
        );

        all_resolved.extend(direct_ancestors);
    }

    Ok(all_resolved)
}

// ─── Phase 1: batch direct CPE matches ──────────────────────────────

/// Batch-resolves direct CPE matches for all rows at once.
///
/// Joins external nodes with describing CPEs in a single query,
/// then resolves node names in a second query.
#[instrument(
    skip(rows, connection),
    fields(count = rows.len()),
    err(level = tracing::Level::INFO)
)]
async fn batch_resolve_direct_cpe_matches(
    rows: &[Row],
    connection: &(impl ConnectionTrait + Send),
) -> Result<Vec<RankedSbom>, Error> {
    if rows.is_empty() {
        return Ok(vec![]);
    }

    let sbom_ids: Vec<_> = rows.iter().map(|r| r.sbom_id).collect();

    // Single query: external nodes with CPE IDs aggregated per (sbom_id, node_ref)
    #[derive(Debug, FromQueryResult)]
    struct ExternalNodeWithCpes {
        sbom_id: Uuid,
        external_node_ref: String,
        cpe_ids: Vec<Uuid>,
    }

    let ext_cpe_rows = sbom_external_node::Entity::find()
        .select_only()
        .column(sbom_external_node::Column::SbomId)
        .column(sbom_external_node::Column::ExternalNodeRef)
        .column_as(
            Expr::cust(r#"array_agg("sbom_describing_cpe"."cpe_id")"#),
            "cpe_ids",
        )
        .join(
            JoinType::Join,
            sbom_external_node::Relation::DescribingCpe.def(),
        )
        .filter(sbom_external_node::Column::SbomId.is_in(sbom_ids))
        .group_by(sbom_external_node::Column::SbomId)
        .group_by(sbom_external_node::Column::ExternalNodeRef)
        .into_model::<ExternalNodeWithCpes>()
        .all(connection)
        .instrument(tracing::info_span!("batch external nodes with cpes").or_current())
        .await
        .map_err(Error::from)?;

    // Batch lookup node names for all referenced external node IDs
    let all_node_ids: Vec<_> = ext_cpe_rows
        .iter()
        .map(|row| row.external_node_ref.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let node_map: HashMap<_, _> = if all_node_ids.is_empty() {
        HashMap::new()
    } else {
        sbom_node::Entity::find()
            .filter(sbom_node::Column::NodeId.is_in(all_node_ids))
            .all(connection)
            .instrument(tracing::info_span!("batch lookup nodes").or_current())
            .await
            .map_err(Error::from)?
            .into_iter()
            .map(|n| (n.node_id.clone(), n))
            .collect()
    };

    // Group by sbom_id for lookup
    let mut ext_cpes_by_sbom: HashMap<Uuid, Vec<(String, Vec<Uuid>)>> = HashMap::new();
    for row in ext_cpe_rows {
        ext_cpes_by_sbom
            .entry(row.sbom_id)
            .or_default()
            .push((row.external_node_ref, row.cpe_ids));
    }

    // Assemble results
    let mut matched_sboms = Vec::new();
    for matched in rows {
        let Some(entries) = ext_cpes_by_sbom.get(&matched.sbom_id) else {
            continue;
        };

        for (node_ref, cpe_ids) in entries {
            let node = node_map.get(node_ref).ok_or_else(|| {
                Error::Data("Ranked matched node has no top ancestor sbom.".to_string())
            })?;

            for cpe_id in cpe_ids {
                matched_sboms.push(RankedSbom {
                    matched_sbom_id: matched.sbom_id,
                    matched_name: node.name.clone(),
                    top_ancestor_sbom: node.sbom_id,
                    cpe_id: *cpe_id,
                    sbom_date: matched.published,
                    rank: None,
                });
            }
        }
    }

    Ok(matched_sboms)
}

// ─── Phase 2: batch ancestor + external resolution ──────────────────

/// Batch-resolves ancestor external SBOMs for all rows.
///
/// 1. One multi-start CTE to find ancestors for all rows
/// 2. Splits rows into top-level vs nested
/// 3. Batch checksum resolution for top-level nodes
/// 4. Batch checksum resolution for root nodes of nested rows,
///    then only recurses deeper via DFS for discovered nodes
///
/// Returns `(row_index, ResolvedSbom)` pairs.
#[instrument(
    skip(connection, context, rows),
    fields(count = rows.len()),
    err(level = tracing::Level::INFO)
)]
async fn batch_resolve_ancestor_externals(
    rows: &[Row],
    connection: &(impl ConnectionTrait + Send),
    context: &mut LoadContext,
) -> Result<Vec<(usize, ResolvedSbom)>, Error> {
    if rows.is_empty() {
        return Ok(vec![]);
    }

    // ── Step 1: batch find_node_ancestors for ALL rows ──
    let pairs: Vec<_> = rows
        .iter()
        .map(|r| (r.sbom_id, r.node_id.clone()))
        .collect();

    let ancestors_by_idx = batch_find_ancestors(connection, context, &pairs).await?;

    // Split rows: top-level (no ancestors) vs nested (has ancestors).
    let mut top_level_pairs = Vec::new();
    let mut nested_entry_points = Vec::new();

    for (idx, row) in rows.iter().enumerate() {
        match ancestors_by_idx.get(&idx) {
            Some(chain) if !chain.is_empty() => {
                for ancestor in chain {
                    nested_entry_points.push((
                        idx,
                        ancestor.sbom_id,
                        ancestor.left_node_id.clone(),
                    ));
                }
            }
            _ => {
                top_level_pairs.push((idx, row.sbom_id, row.node_id.clone()));
            }
        }
    }

    let mut all_externals = Vec::new();

    // ── Step 2: batch checksum for top-level nodes ──
    if !top_level_pairs.is_empty() {
        let checksum_pairs: Vec<_> = top_level_pairs
            .iter()
            .map(|(_, sid, nid)| (*sid, nid.clone()))
            .collect();

        let resolved =
            batch_resolve_rh_external_sbom_ancestors(connection, &checksum_pairs).await?;

        for (i, (idx, _, _)) in top_level_pairs.iter().enumerate() {
            let key = (checksum_pairs[i].0, checksum_pairs[i].1.clone());
            if let Some(externals) = resolved.get(&key) {
                for ext in externals {
                    all_externals.push((*idx, ext.clone()));
                }
            }
        }
    }

    // ── Step 3: batch checksum for nested entry points ──
    if !nested_entry_points.is_empty() {
        // 3a. Deduplicate entry points
        let unique_pairs: Vec<_> = nested_entry_points
            .iter()
            .map(|(_, sid, nid)| (*sid, nid.clone()))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let resolved = batch_resolve_rh_external_sbom_ancestors(connection, &unique_pairs).await?;

        // 3b. Collect first-level ancestors, then batch find_node_ancestors
        let mut all_first_level = Vec::new();
        for ancestors in resolved.values() {
            for a in ancestors {
                all_first_level.push(a.clone());
            }
        }

        let unique_ancestors: Vec<_> = all_first_level
            .iter()
            .map(|a| (a.sbom_id, a.node_id.clone()))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let ancestor_roots = batch_find_ancestors(connection, context, &unique_ancestors).await?;

        // Build lookup: (ancestor_sbom_id, ancestor_node_id) -> root packages
        let mut roots_by_ancestor = HashMap::new();
        for (i, key) in unique_ancestors.iter().enumerate() {
            if let Some(chain) = ancestor_roots.get(&i) {
                roots_by_ancestor.insert(key.clone(), chain);
            }
        }

        // 3c. Collect DFS entry points from root nodes
        let mut dfs_entries = Vec::new();
        for (key, chain) in &roots_by_ancestor {
            if chain.is_empty() {
                dfs_entries.push(key.clone());
            } else {
                for pkg in *chain {
                    dfs_entries.push((pkg.sbom_id, pkg.left_node_id.clone()));
                }
            }
        }

        let unique_dfs: Vec<_> = dfs_entries
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let dfs_first_level =
            batch_resolve_rh_external_sbom_ancestors(connection, &unique_dfs).await?;

        // 3d. Fan results back to input rows, recurse deeper via DFS
        let mut entries_by_row: HashMap<_, Vec<_>> = HashMap::new();
        for (idx, sid, nid) in &nested_entry_points {
            entries_by_row
                .entry(*idx)
                .or_default()
                .push((*sid, nid.clone()));
        }

        for (idx, entry_keys) in &entries_by_row {
            let mut visited = HashSet::new();

            for entry_key in entry_keys {
                let first_level = resolved.get(entry_key).cloned().unwrap_or_default();

                for ancestor in first_level {
                    let ancestor_key = (ancestor.sbom_id, ancestor.node_id.clone());

                    let root_chain = roots_by_ancestor.get(&ancestor_key).copied();

                    let root_entries: Vec<_> = match root_chain {
                        Some(chain) if !chain.is_empty() => chain
                            .iter()
                            .map(|p| (p.sbom_id, p.left_node_id.clone()))
                            .collect(),
                        _ => vec![ancestor_key],
                    };

                    for root_key in &root_entries {
                        let dfs_results =
                            dfs_first_level.get(root_key).cloned().unwrap_or_default();

                        for deep_ancestor in dfs_results {
                            if !visited
                                .insert((deep_ancestor.sbom_id, deep_ancestor.node_id.clone()))
                            {
                                continue;
                            }

                            // Recurse for level 2+ (rare)
                            let top_pkgs = find_node_ancestors(
                                deep_ancestor.sbom_id,
                                deep_ancestor.node_id.clone(),
                                connection,
                                context,
                            )
                            .await?;

                            for pkg in top_pkgs {
                                let deep = find_external_refs(
                                    pkg.sbom_id,
                                    pkg.left_node_id,
                                    connection,
                                    context,
                                    &mut visited,
                                )
                                .await?;
                                for ext in deep {
                                    all_externals.push((*idx, ext));
                                }
                            }

                            all_externals.push((*idx, deep_ancestor));
                        }
                    }

                    all_externals.push((*idx, ancestor));
                }
            }
        }
    }

    Ok(all_externals)
}

// ─── Top-level orchestrator ─────────────────────────────────────────

/// Resolve CPEs for matched SBOMs using batched queries.
///
/// Processes all rows in phases to minimize database round-trips:
/// 1. Batch direct CPE matches (when `cpe_search` is true)
/// 2. Batch ancestor resolution + external SBOM discovery (includes CPEs)
#[instrument(skip(connection, rows), fields(rows = rows.len()))]
pub async fn resolve_sbom_cpes(
    cpe_search: bool,
    connection: &(impl ConnectionTrait + Send),
    rows: Vec<Row>,
) -> Result<Vec<RankedSbom>, Error> {
    let mut results = Vec::new();
    let mut context = LoadContext::default();

    // ── Phase 1: batch direct CPE matches (cpe_search only) ──
    if cpe_search {
        let direct = batch_resolve_direct_cpe_matches(&rows, connection).await?;
        results.extend(direct);
    }

    // ── Phase 2: batch ancestor + external resolution ──
    let all_externals = batch_resolve_ancestor_externals(&rows, connection, &mut context).await?;

    // ── Phase 3: map external SBOMs to RankedSboms via their CPEs ──
    for (idx, ext) in &all_externals {
        let matched = &rows[*idx];
        results.extend(ext.cpe_ids.iter().map(|cpe_id| RankedSbom {
            matched_sbom_id: matched.sbom_id,
            matched_name: matched.name.clone(),
            top_ancestor_sbom: ext.sbom_id,
            cpe_id: *cpe_id,
            sbom_date: matched.published,
            rank: None,
        }));
    }

    log::info!("Cache stats: {context:?}");

    Ok(results)
}

// ─── Ranking ────────────────────────────────────────────────────────

/// Assigns a rank to SBOMs within their specific CPE groups based on
/// creation date which embodies the latest filter heuristics.
///
/// Simulates a SQL Window Function:
/// `DENSE_RANK() OVER (PARTITION BY cpe_id ORDER BY sbom_date DESC)`.
///
/// 1. **Sort** by `cpe_id`, `name`, then `sbom_date` descending.
/// 2. **Rank**: resets on group boundary, ties share rank, otherwise increments (dense rank).
pub fn apply_rank(items: &mut [RankedSbom]) {
    items.sort_by(|a, b| {
        a.cpe_id
            .cmp(&b.cpe_id)
            .then(a.matched_name.cmp(&b.matched_name))
            .then(b.sbom_date.cmp(&a.sbom_date))
    });

    let mut current_rank = 1;

    for i in 0..items.len() {
        if i == 0 {
            items[i].rank = Some(1);
            continue;
        }

        let prev = &items[i - 1];
        let curr = &items[i];

        let same_partition = curr.cpe_id == prev.cpe_id && curr.matched_name == prev.matched_name;

        if same_partition {
            if curr.sbom_date == prev.sbom_date {
                items[i].rank = items[i - 1].rank;
            } else {
                current_rank += 1;
                items[i].rank = Some(current_rank);
            }
        } else {
            current_rank = 1;
            items[i].rank = Some(1);
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

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

        let cpe_ids = sbom_describing_cpe::Entity::find()
            .select_only()
            .column(sbom_describing_cpe::Column::CpeId)
            .filter(sbom_describing_cpe::Column::SbomId.eq(product))
            .into_tuple::<Uuid>()
            .all(&ctx.db)
            .await?;

        let cpes = stream::iter(cpe_ids)
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
                    cpe_ids: vec![],
                },
                ResolvedSbom {
                    sbom_id: _id_b,
                    node_id: "SPDXRef-Leaf-B".into(),
                    cpe_ids: vec![],
                },
            ]
        );

        Ok(())
    }
}
