use crate::Error;
use sea_orm::{
    ConnectionTrait, DatabaseBackend, EntityTrait, FromQueryResult, JoinType, QueryFilter,
    QuerySelect, RelationTrait, Select, Statement,
};
use sea_query::{Expr, PgFunc};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use tracing::{Instrument, instrument};
#[cfg(test)]
use trustify_entity::sbom_describing_cpe;
use trustify_entity::{sbom, sbom_external_node, sbom_node};
use uuid::Uuid;

#[derive(Debug, Clone, FromQueryResult)]
pub struct Row {
    /// The matched SBOM
    pub sbom_id: Uuid,
    /// The node inside the matched SBOM
    #[allow(dead_code)] // used by callers outside this module
    pub node_id: String,
    /// name of the matched node
    pub name: String,
    /// publish time of the SBOM that matched
    pub published: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedSbom {
    pub matched_sbom_id: Uuid,
    pub matched_name: String,
    #[cfg(test)]
    pub top_ancestor_sbom: Uuid,
    pub cpe_id: Uuid,
    pub sbom_date: OffsetDateTime,
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

    let sbom_ids: Vec<_> = rows
        .iter()
        .map(|r| r.sbom_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

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
        .filter(
            Expr::col((
                sbom_external_node::Entity,
                sbom_external_node::Column::SbomId,
            ))
            .eq(PgFunc::any(sbom_ids)),
        )
        .group_by(sbom_external_node::Column::SbomId)
        .group_by(sbom_external_node::Column::ExternalNodeRef)
        .into_model::<ExternalNodeWithCpes>()
        .all(connection)
        .instrument(tracing::info_span!("batch external nodes with cpes").or_current())
        .await
        .map_err(Error::from)?;

    // Batch lookup node names for all referenced external node IDs.
    // Collect all matches per node_id so we can resolve the right target
    // when multiple SBOMs share the same node_id string.
    let all_node_ids: Vec<_> = ext_cpe_rows
        .iter()
        .map(|row| row.external_node_ref.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let mut node_map: HashMap<String, Vec<sbom_node::Model>> = HashMap::new();
    if !all_node_ids.is_empty() {
        let nodes = sbom_node::Entity::find()
            .filter(
                Expr::col((sbom_node::Entity, sbom_node::Column::NodeId))
                    .eq(PgFunc::any(all_node_ids)),
            )
            .all(connection)
            .instrument(tracing::info_span!("batch lookup nodes").or_current())
            .await
            .map_err(Error::from)?;
        for n in nodes {
            node_map.entry(n.node_id.clone()).or_default().push(n);
        }
    }

    // Group by sbom_id for lookup
    let mut ext_cpes_by_sbom: HashMap<Uuid, Vec<(String, Vec<Uuid>)>> = HashMap::new();
    for row in ext_cpe_rows {
        ext_cpes_by_sbom
            .entry(row.sbom_id)
            .or_default()
            .push((row.external_node_ref, row.cpe_ids));
    }

    // Assemble results. When looking up the node for an external_node_ref,
    // prefer a match outside the source SBOM (the actual target), falling
    // back to the first available match.
    let mut matched_sboms = Vec::new();
    for matched in rows {
        let Some(entries) = ext_cpes_by_sbom.get(&matched.sbom_id) else {
            continue;
        };

        for (node_ref, cpe_ids) in entries {
            let candidates = node_map.get(node_ref).ok_or_else(|| {
                Error::Data("Ranked matched node has no top ancestor sbom.".to_string())
            })?;

            let node = candidates
                .iter()
                .find(|n| n.sbom_id != matched.sbom_id)
                .unwrap_or(&candidates[0]);

            for cpe_id in cpe_ids {
                matched_sboms.push(RankedSbom {
                    matched_sbom_id: matched.sbom_id,
                    matched_name: node.name.clone(),
                    #[cfg(test)]
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

// ─── Phase 2: ancestor CPEs via materialized sbom_ancestor table ───

/// Result row from the ancestor CPE query.
#[derive(Debug, FromQueryResult)]
struct AncestorCpeRow {
    sbom_id: Uuid,
    cpe_id: Uuid,
}

/// Resolves ancestor CPEs for matched SBOMs using the materialized
/// `sbom_ancestor` table, in two sub-phases.
///
/// Phase 2a (non-recursive): for all matched SBOMs without own
/// describing CPEs, find direct ancestors with CPEs. Handles the
/// common case of image-index → product (one hop).
///
/// Phase 2b (recursive): for SBOMs where 2a found nothing, walk
/// the full ancestor chain. Handles multi-hop paths like binary →
/// image-index → product. Results are returned separately so the
/// caller can dedup Phase 2b against Phase 1.
#[instrument(skip(connection, sbom_ids), fields(count = sbom_ids.len()))]
async fn batch_resolve_ancestor_cpes(
    sbom_ids: &[Uuid],
    connection: &(impl ConnectionTrait + Send),
) -> Result<(Vec<AncestorCpeRow>, Vec<AncestorCpeRow>), Error> {
    if sbom_ids.is_empty() {
        return Ok((vec![], vec![]));
    }

    // Phase 2a: direct ancestors with CPEs (non-recursive, one hop)
    let direct_stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        r#"
        SELECT DISTINCT sa.sbom_id, sdc.cpe_id
        FROM sbom_ancestor sa
        JOIN sbom_describing_cpe sdc ON sdc.sbom_id = sa.ancestor_sbom_id
        WHERE sa.sbom_id = ANY($1)
          AND NOT EXISTS (
              SELECT 1 FROM sbom_describing_cpe own
              WHERE own.sbom_id = sa.sbom_id
          )
        "#,
        [sbom_ids.to_vec().into()],
    );

    let direct: Vec<AncestorCpeRow> = AncestorCpeRow::find_by_statement(direct_stmt)
        .all(connection)
        .instrument(tracing::info_span!("phase 2a: direct ancestor cpes").or_current())
        .await?;

    // Determine which SBOMs still need recursive resolution
    let covered: HashSet<Uuid> = direct.iter().map(|r| r.sbom_id).collect();

    let uncovered: Vec<Uuid> = sbom_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|id| !covered.contains(id))
        .collect();

    if uncovered.is_empty() {
        return Ok((direct, vec![]));
    }

    // Phase 2b: recursive ancestor walk for remaining SBOMs
    let recursive_stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        r#"
        WITH RECURSIVE transitive AS (
            SELECT sa.sbom_id, sa.ancestor_sbom_id, 1 AS depth
            FROM sbom_ancestor sa
            WHERE sa.sbom_id = ANY($1)
              AND NOT EXISTS (
                  SELECT 1 FROM sbom_describing_cpe own
                  WHERE own.sbom_id = sa.sbom_id
              )
            UNION
            SELECT t.sbom_id, sa.ancestor_sbom_id, t.depth + 1
            FROM transitive t
            JOIN sbom_ancestor sa ON sa.sbom_id = t.ancestor_sbom_id
            WHERE t.sbom_id != sa.ancestor_sbom_id
              AND t.depth < 10
        )
        SELECT DISTINCT t.sbom_id, sdc.cpe_id
        FROM transitive t
        JOIN sbom_describing_cpe sdc ON sdc.sbom_id = t.ancestor_sbom_id
        "#,
        [uncovered.into()],
    );

    let recursive: Vec<AncestorCpeRow> = AncestorCpeRow::find_by_statement(recursive_stmt)
        .all(connection)
        .instrument(tracing::info_span!("phase 2b: recursive ancestor cpes").or_current())
        .await?;

    Ok((direct, recursive))
}

// ─── Top-level orchestrator ─────────────────────────────────────────

/// Resolve CPEs for matched SBOMs using the materialized `sbom_ancestor` table.
///
/// Processes all rows in two phases:
/// 1. Batch direct CPE matches (when `cpe_search` is true) — explicit
///    `sbom_external_node` references where the matched SBOM itself has CPEs
/// 2. Ancestor CPE lookup via `sbom_ancestor` + `sbom_describing_cpe` — replaces
///    the expensive runtime graph walking and checksum matching
#[instrument(skip(connection, rows), fields(rows = rows.len()))]
pub async fn resolve_sbom_cpes(
    cpe_search: bool,
    connection: &(impl ConnectionTrait + Send),
    rows: Vec<Row>,
) -> Result<Vec<RankedSbom>, Error> {
    let mut results = Vec::new();

    // ── Phase 1: batch direct CPE matches (cpe_search only) ──
    if cpe_search {
        results.extend(batch_resolve_direct_cpe_matches(&rows, connection).await?);
    }

    // ── Phase 2: ancestor CPEs via materialized table ──
    let sbom_ids: Vec<_> = rows
        .iter()
        .map(|r| r.sbom_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let (phase2a, phase2b) = batch_resolve_ancestor_cpes(&sbom_ids, connection).await?;

    let rows_by_sbom: HashMap<Uuid, Vec<&Row>> = {
        let mut map: HashMap<Uuid, Vec<&Row>> = HashMap::new();
        for row in &rows {
            map.entry(row.sbom_id).or_default().push(row);
        }
        map
    };

    // Phase 2a results are always included (non-recursive, direct ancestors)
    for ancestor_cpe in &phase2a {
        if let Some(matched_rows) = rows_by_sbom.get(&ancestor_cpe.sbom_id) {
            for matched in matched_rows {
                results.push(RankedSbom {
                    matched_sbom_id: matched.sbom_id,
                    matched_name: matched.name.clone(),
                    #[cfg(test)]
                    top_ancestor_sbom: Uuid::nil(),
                    cpe_id: ancestor_cpe.cpe_id,
                    sbom_date: matched.published,
                    rank: None,
                });
            }
        }
    }

    // Build dedup set from Phase 1 + Phase 2a using owned strings
    // to avoid borrowing `results` while we push to it below
    let existing: HashSet<(Uuid, String)> = results
        .iter()
        .map(|r| (r.cpe_id, r.matched_name.clone()))
        .collect();

    // Phase 2b results are deduped against the combined set — only
    // genuinely new (cpe, name) pairs pass through. This prevents
    // recursive traversal from re-adding entries that Phase 1 already
    // covers (e.g. binary SBOMs sharing a name with product SBOMs),
    // while allowing novel components like nested RPMs through.
    for ancestor_cpe in &phase2b {
        if let Some(matched_rows) = rows_by_sbom.get(&ancestor_cpe.sbom_id) {
            for matched in matched_rows {
                if existing.contains(&(ancestor_cpe.cpe_id, matched.name.clone())) {
                    continue;
                }
                results.push(RankedSbom {
                    matched_sbom_id: matched.sbom_id,
                    matched_name: matched.name.clone(),
                    #[cfg(test)]
                    top_ancestor_sbom: Uuid::nil(),
                    cpe_id: ancestor_cpe.cpe_id,
                    sbom_date: matched.published,
                    rank: None,
                });
            }
        }
    }

    Ok(results)
}

// ─── Ranking ────────────────────────────────────────────────────────

/// Assigns a rank to SBOMs within their specific CPE groups based on
/// creation date which embodies the latest filter heuristics.
///
/// Simulates a SQL Window Function:
/// `DENSE_RANK() OVER (PARTITION BY (cpe_id, matched_name) ORDER BY sbom_date DESC)`.
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
    use futures::{StreamExt, TryStreamExt, stream};
    use rstest::rstest;
    use sea_orm::ColumnTrait;
    use test_context::test_context;
    use time::macros::datetime;
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

    /// Verify that ingesting linked SBOMs populates the `sbom_ancestor` table
    /// with a unidirectional (child, ancestor) entry based on external node
    /// checksum matching.
    #[test_context(TrustifyContext)]
    #[test_log::test(actix_web::test)]
    async fn populate_ancestors(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let [product, rpm] = ctx.ingest_documents(rpm::older()).await?.into_uuid();

        let ancestors: Vec<trustify_entity::sbom_ancestor::Model> =
            trustify_entity::sbom_ancestor::Entity::find()
                .all(&ctx.db)
                .await?;

        let has_forward = ancestors
            .iter()
            .any(|a| a.sbom_id == rpm && a.ancestor_sbom_id == product);

        assert!(has_forward, "expected rpm -> product link");
        assert_eq!(
            ancestors.len(),
            1,
            "expected exactly one unidirectional link"
        );

        Ok(())
    }

    /// Create a simple [`RankedSbom`] for testing.
    fn ranked(
        sbom: Uuid,
        name: &str,
        cpe_id: Uuid,
        date: OffsetDateTime,
        rank: usize,
    ) -> RankedSbom {
        RankedSbom {
            matched_sbom_id: sbom,
            matched_name: name.to_string(),
            top_ancestor_sbom: Default::default(),
            cpe_id,
            sbom_date: date,
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

    fn utc(day: u8) -> OffsetDateTime {
        datetime!(2025-01-01 0:00 UTC) + time::Duration::days(i64::from(day) - 1)
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

    /// Verifies that `batch_resolve_direct_cpe_matches` resolves the
    /// correct node name when multiple SBOMs share the same `node_id`.
    ///
    /// The product SBOM has an external reference with
    /// `external_node_ref = "shared-ref"`. Both the target and decoy SBOMs
    /// have a component with `bom-ref = "shared-ref"` but different names.
    /// The lookup must pick a non-source SBOM rather than colliding.
    #[test_context(TrustifyContext)]
    #[test_log::test(tokio::test)]
    async fn node_id_collision_in_cpe_lookup(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let [product_id, _target_id, _decoy_id] = ctx
            .ingest_documents([
                "cyclonedx/node-id-collision/product.json",
                "cyclonedx/node-id-collision/target.json",
                "cyclonedx/node-id-collision/decoy.json",
            ])
            .await?
            .into_uuid();

        let rows = vec![Row {
            sbom_id: product_id,
            node_id: "comp-a".into(),
            name: "ComponentA".into(),
            published: datetime!(2025-01-01 0:00 UTC),
        }];

        let ranked = resolve_sbom_cpes(true, &ctx.db, rows).await?;

        log::debug!("ranked results: {ranked:#?}");

        assert!(!ranked.is_empty(), "expected at least one result");

        for result in &ranked {
            assert_ne!(
                result.top_ancestor_sbom, product_id,
                "top_ancestor_sbom should NOT be the source SBOM"
            );
            assert!(
                result.matched_name == "SharedComponent" || result.matched_name == "DecoyComponent",
                "matched_name should come from a target SBOM, got: {}",
                result.matched_name
            );
        }

        Ok(())
    }
}
