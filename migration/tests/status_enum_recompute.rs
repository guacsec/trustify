// The nested async blocks in these tests (ingest + repeated migrate + query)
// push the type-layout computation past rustc's default recursion limit.
#![recursion_limit = "256"]
// Integration-test helpers (not `#[test]`-annotated) legitimately `unwrap`/`expect`
// on setup and query results; clippy's `allow-*-in-tests` doesn't reach them, so
// allow both crate-wide here, mirroring `modules/ingestor/tests/issues.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration coverage for the in-place primary-key recompute performed by
//! `m0002320_replace_status_with_enum` (TC-4488).
//!
//! The migration changes the first link of each status row's `Uuid::new_v5`
//! chain from the status *UUID* bytes to the status *slug*, so every
//! `purl_status` / `product_status` / `cpe_status` id is regenerated and the
//! `remediation_*_status` children must follow. These tests exercise that
//! recompute against a fully-migrated database by reverting exactly the last
//! migration (`down(1)`) and reapplying it (`up(1)`):
//!
//! * [`recompute_preserves_ingested_ids`] ingests real advisories, then asserts
//!   a `down`/`up` cycle leaves every id and every remediation link untouched —
//!   i.e. the migration's recompute agrees byte-for-byte with the ingestor's
//!   `*_status_id` functions and drops no rows.
//! * [`recompute_dedupes_duplicate_fixed_purl_status`],
//!   [`recompute_dedupes_duplicate_fixed_product_status`] and
//!   [`recompute_collapses_duplicate_fixed_cpe_status`] reproduce the
//!   duplicate-`fixed` seed collision (two `status` rows share the `fixed` slug)
//!   for each of the three tables and assert the two colliding parents — and, for
//!   the two tables that have them, their remediation children — collapse onto a
//!   single survivor whose id matches the ingestor.
//! * [`recompute_repoints_loser_only_remediation_child`] covers the asymmetric
//!   case where only the *loser* of the collision carries a remediation child:
//!   it must be repointed to the survivor, not dropped with the loser parent.
//! * [`recompute_unions_csaf_product_ids_on_collapse`],
//!   [`recompute_unions_csaf_product_ids_into_null_survivor`] and
//!   [`recompute_leaves_all_null_csaf_product_ids_null`] cover the one non-hashed
//!   column (`product_status.csaf_product_ids`) two colliding rows can differ in:
//!   the survivor must end up with the sorted union of both (even when the
//!   survivor's own value is `NULL`, and `NULL` itself when both are empty), while
//!   non-colliding rows are left byte-for-byte untouched.

use migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_module_ingestor::graph::advisory::{
    cpe_status::cpe_status_id, product_status::product_status_id, purl_status::purl_status_id,
};
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

/// The `id` PKs of `table`, sorted, so two snapshots compare order-independently.
async fn ids<C: ConnectionTrait>(conn: &C, table: &str) -> Vec<Uuid> {
    conn.query_all(Statement::from_string(
        DatabaseBackend::Postgres,
        format!("SELECT id FROM {table} ORDER BY id"),
    ))
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get::<Uuid>("", "id").unwrap())
    .collect()
}

/// The `(remediation_id, <fk_col>)` links of a `remediation_*_status` child
/// table, sorted.
async fn child_pairs<C: ConnectionTrait>(conn: &C, table: &str, fk_col: &str) -> Vec<(Uuid, Uuid)> {
    let mut pairs: Vec<(Uuid, Uuid)> = conn
        .query_all(Statement::from_string(
            DatabaseBackend::Postgres,
            format!("SELECT remediation_id, {fk_col} AS fk FROM {table}"),
        ))
        .await
        .unwrap()
        .iter()
        .map(|r| {
            (
                r.try_get::<Uuid>("", "remediation_id").unwrap(),
                r.try_get::<Uuid>("", "fk").unwrap(),
            )
        })
        .collect();
    pairs.sort();
    pairs
}

/// Runs a `count(*) AS n` statement and returns the scalar.
async fn count<C: ConnectionTrait>(conn: &C, stmt: Statement) -> i64 {
    conn.query_one(stmt)
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
}

fn u(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// The two seeded `fixed` status UUIDs (`m0000010_init_up.sql`), as restored by
/// `down(1)`. The pre-enum seed contained two different rows sharing the `fixed`
/// slug, which is what the recompute has to collapse.
async fn fixed_status_ids<C: ConnectionTrait>(conn: &C) -> Vec<Uuid> {
    conn.query_all(Statement::from_string(
        DatabaseBackend::Postgres,
        "SELECT id FROM status WHERE slug = 'fixed' ORDER BY id".to_owned(),
    ))
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get::<Uuid>("", "id").unwrap())
    .collect()
}

/// Fails with an actionable message if reverting the last migration did not leave
/// the `status` *table* in place. `down(1)` reverts whatever migration is last, so
/// once m0002320 stops being last it would revert something else and leave
/// `status` as the enum type it creates. Every fixture below then reads `status`
/// as a table; without this check the first such query would instead panic on a
/// cryptic `relation "status" does not exist` deep inside a helper.
async fn assert_status_table_restored(db: &Database) {
    let tables = count(
        db,
        Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT count(*) AS n FROM information_schema.tables \
             WHERE table_name = 'status' AND table_type = 'BASE TABLE'"
                .to_owned(),
        ),
    )
    .await;
    assert_eq!(
        tables, 1,
        "down(1) did not restore the `status` table; m0002320 may no longer be \
         the last migration (down(1) reverts whatever migration is last)"
    );
}

/// Which crafted parent(s) carry a remediation child.
#[derive(Clone, Copy)]
enum ChildOn {
    /// One child on each crafted parent — both must collapse onto a single link.
    Both,
    /// A child on the loser (`u(2)`, the larger old id) only. `apply_remap`
    /// deletes a child only when a *sibling* child on a smaller old id exists, so
    /// a lone child on the loser must be repointed to the survivor rather than
    /// dropped with the loser parent — the data-loss-prone path.
    LoserOnly,
}

/// A remediation child to hang off the crafted duplicate-`fixed` rows.
struct Child<'a> {
    /// `remediation_purl_status` / `remediation_product_status`.
    table: &'a str,
    /// The FK column pointing back at the parent's `id`.
    fk_col: &'a str,
    /// Which crafted parent(s) get a child.
    on: ChildOn,
    /// FK parents for the synthetic `remediation` row (must reference a real
    /// `advisory_vulnerability`).
    advisory_id: Uuid,
    vulnerability_id: String,
}

/// Crafts the duplicate-`fixed` collision for `table` and asserts the recompute
/// collapses it onto `expected`.
///
/// Precondition: the database is at the reverted (status-table) schema, `table`
/// holds a real row `template_id` to clone FK values from, and `fixed_ids` are
/// the two seeded `fixed` UUIDs. This inserts two rows identical to the template
/// except for their `fixed` status_id. The crafted ids are the fixed ordered
/// constants `u(1)` < `u(2)`, so `mark_survivors` deterministically keeps `u(1)`;
/// they are also far below any real v5 hash, so they cannot collide with the
/// recomputed `expected` id (asserted as a precondition). It optionally attaches
/// remediation children (on both parents, or the loser only — see [`ChildOn`]),
/// runs `up(1)`, and asserts the parents — and any children — collapse onto the
/// single ingestor-computed `expected` id.
async fn assert_fixed_dedup(
    db: &Database,
    table: &str,
    copy_cols: &[&str],
    template_id: Uuid,
    fixed_ids: &[Uuid],
    expected: Uuid,
    child: Option<Child<'_>>,
) {
    let (row1, row2) = (u(1), u(2));
    let cols = copy_cols.join(", ");

    // Two rows identical to the template except for which `fixed` UUID they use —
    // the exact pre-migration shape that later collapses. Cloning from one
    // template makes both share every non-key column, so the collapse's discard
    // of the loser is lossless *in this test*. That is not universal in
    // production: purl_status/cpe_status hash every non-key column (any two rows
    // that collapse are therefore identical elsewhere), but product_status also
    // stores `csaf_product_ids`, which is not a hash input — two real rows could
    // collapse yet differ there, so the migration unions that column into the
    // survivor. This helper does not exercise that (both rows are cloned from one
    // template, so they are identical); the differing case is covered by
    // `recompute_unions_csaf_product_ids_on_collapse` and
    // `recompute_unions_csaf_product_ids_into_null_survivor`.
    for (row_id, fixed_id) in [(row1, fixed_ids[0]), (row2, fixed_ids[1])] {
        db.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            format!(
                "INSERT INTO {table} (id, status_id, {cols}) \
                 SELECT $1, $2, {cols} FROM {table} WHERE id = $3"
            ),
            [row_id.into(), fixed_id.into(), template_id.into()],
        ))
        .await
        .unwrap();
    }

    // Optionally, a remediation with one child per targeted parent; after the
    // collapse every child must end up on the survivor's (remediation_id, id)
    // composite PK.
    let remediation_id = if let Some(child) = &child {
        let rem_id = Uuid::new_v4();
        db.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "INSERT INTO remediation (id, advisory_id, vulnerability_id, category, data) \
             VALUES ($1, $2, $3, 'vendor_fix', '{}'::jsonb)",
            [
                rem_id.into(),
                child.advisory_id.into(),
                child.vulnerability_id.clone().into(),
            ],
        ))
        .await
        .unwrap();
        let targets: &[Uuid] = match child.on {
            ChildOn::Both => &[row1, row2],
            ChildOn::LoserOnly => &[row2],
        };
        for &target in targets {
            db.execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                format!(
                    "INSERT INTO {} (remediation_id, {}) VALUES ($1, $2)",
                    child.table, child.fk_col
                ),
                [rem_id.into(), target.into()],
            ))
            .await
            .unwrap();
        }
        Some(rem_id)
    } else {
        None
    };

    // Preconditions: two distinct crafted parents, and nothing yet occupying the
    // collapsed id (or the test would falsely pass).
    assert_eq!(
        count(
            db,
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table} WHERE id IN ($1, $2)"),
                [row1.into(), row2.into()],
            ),
        )
        .await,
        2,
        "expected two crafted {table} rows before recompute"
    );
    assert_eq!(
        count(
            db,
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table} WHERE id = $1"),
                [expected.into()],
            ),
        )
        .await,
        0,
        "the collapsed {table} id must not pre-exist, or the test would falsely pass"
    );
    if let (Some(child), Some(rem_id)) = (&child, remediation_id) {
        let crafted = match child.on {
            ChildOn::Both => 2,
            ChildOn::LoserOnly => 1,
        };
        assert_eq!(
            count(
                db,
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    format!(
                        "SELECT count(*) AS n FROM {} WHERE remediation_id = $1",
                        child.table
                    ),
                    [rem_id.into()],
                ),
            )
            .await,
            crafted,
            "expected {crafted} crafted {} rows before recompute",
            child.table
        );
        if let ChildOn::LoserOnly = child.on {
            // The whole point of this case is that the lone child hangs off the
            // *loser* (u(2)). Pin it here: if the fixture ever silently placed it
            // on the survivor instead, the postconditions below would still pass
            // (a survivor child is trivially kept), degrading this into a
            // duplicate of the symmetric test without anyone noticing.
            assert_eq!(
                count(
                    db,
                    Statement::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        format!(
                            "SELECT count(*) AS n FROM {} WHERE remediation_id = $1 AND {} = $2",
                            child.table, child.fk_col
                        ),
                        [rem_id.into(), row2.into()],
                    ),
                )
                .await,
                1,
                "the LoserOnly {} child must be crafted on the loser id u(2)",
                child.table
            );
        }
    }

    // Total parents before the collapse, so we can prove exactly one row
    // disappears. This rules out a wrongful delete-of-both that a real row
    // happening to recompute to `expected` could otherwise mask — the exposed
    // case is the child-less cpe table, whose only other check is the parent
    // counts below.
    let parents_before = count(
        db,
        Statement::from_string(
            DatabaseBackend::Postgres,
            format!("SELECT count(*) AS n FROM {table}"),
        ),
    )
    .await;

    // Reapply the migration: recompute + dedup.
    Migrator::up(db, Some(1)).await.unwrap();

    // Both crafted parents collapsed onto the single ingestor-computed id.
    assert_eq!(
        count(
            db,
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table} WHERE id = $1"),
                [expected.into()],
            ),
        )
        .await,
        1,
        "duplicate `fixed` {table} parents did not collapse onto the recomputed id"
    );
    assert_eq!(
        count(
            db,
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table} WHERE id IN ($1, $2)"),
                [row1.into(), row2.into()],
            ),
        )
        .await,
        0,
        "the pre-migration crafted {table} ids should no longer exist"
    );
    assert_eq!(
        count(
            db,
            Statement::from_string(
                DatabaseBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table}"),
            ),
        )
        .await,
        parents_before - 1,
        "exactly one {table} row (the collapsed duplicate) should disappear; \
         a different delta means the migration dropped or added rows instead of \
         collapsing the two crafted duplicates onto one survivor"
    );
    if let (Some(child), Some(rem_id)) = (&child, remediation_id) {
        // Exactly one child remains, and it points at the survivor: this catches
        // both a failure to dedup/repoint (Both) and a lone loser-child being
        // wrongly dropped or duplicated (LoserOnly).
        assert_eq!(
            count(
                db,
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    format!(
                        "SELECT count(*) AS n FROM {} WHERE remediation_id = $1",
                        child.table
                    ),
                    [rem_id.into()],
                ),
            )
            .await,
            1,
            "expected exactly one surviving {} child after recompute",
            child.table
        );
        assert_eq!(
            count(
                db,
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    format!(
                        "SELECT count(*) AS n FROM {} WHERE remediation_id = $1 AND {} = $2",
                        child.table, child.fk_col
                    ),
                    [rem_id.into(), expected.into()],
                ),
            )
            .await,
            1,
            "the surviving {} child does not point at the recomputed survivor id",
            child.table
        );
    }
}

/// Reverting then reapplying the migration against real ingested data must leave
/// every status id and remediation link exactly as the ingestor wrote them.
///
/// Because ingested ids are *already* slug-based, this test does not prove the
/// recompute relocates anything — an accidental no-op recompute would also pass.
/// That guarantee lives in the `*_duplicate_fixed_*` tests, which move crafted
/// ids onto a new survivor. What this test uniquely catches is a migration that
/// reads the *wrong* stored column into a hash parameter (or in the wrong order),
/// or that drops rows: either would change or lose an id versus the ingestor's
/// independent in-memory construction. The two kinds of test are complementary —
/// neither subsumes the other.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_preserves_ingested_ids(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    // A CSAF advisory populates purl_status/product_status (+ remediation
    // children); a CVE advisory populates cpe_status.
    ctx.ingest_documents(["csaf/cve-2023-33201.json", "cve/CVE-2099-0001.json"])
        .await?;

    let db = &ctx.db;

    let purl_before = ids(db, "purl_status").await;
    let product_before = ids(db, "product_status").await;
    let cpe_before = ids(db, "cpe_status").await;
    let rem_purl_before = child_pairs(db, "remediation_purl_status", "purl_status_id").await;
    let rem_product_before =
        child_pairs(db, "remediation_product_status", "product_status_id").await;

    // Guard the fixtures: a silent change that stopped producing status rows or
    // remediation links would turn the matching assertions below into vacuous
    // passes.
    assert!(
        !purl_before.is_empty(),
        "CSAF fixture should produce purl_status rows"
    );
    assert!(
        !product_before.is_empty(),
        "CSAF fixture should produce product_status rows"
    );
    assert!(
        !cpe_before.is_empty(),
        "CVE fixture should produce cpe_status rows"
    );
    assert!(
        !rem_purl_before.is_empty(),
        "CSAF fixture should produce remediation_purl_status links"
    );
    assert!(
        !rem_product_before.is_empty(),
        "CSAF fixture should produce remediation_product_status links"
    );

    // Revert exactly m0002320 (the last migration) back to the status-table
    // schema, then reapply it — recomputing every id from scratch.
    Migrator::down(db, Some(1)).await?;

    // `down(1)` reverts whatever migration is *last*, so if m0002320 stopped being
    // last the id assertions below would pass vacuously against an unrelated
    // revert. These two guards fail loudly instead: the first that the `status`
    // table is back at all, the second that its two `fixed` seed rows survived.
    assert_status_table_restored(db).await;
    assert_eq!(
        fixed_status_ids(db).await.len(),
        2,
        "restored status table should still carry its two `fixed` seed rows"
    );

    Migrator::up(db, Some(1)).await?;

    assert_eq!(
        ids(db, "purl_status").await,
        purl_before,
        "purl_status ids changed across down+up"
    );
    assert_eq!(
        ids(db, "product_status").await,
        product_before,
        "product_status ids changed across down+up"
    );
    assert_eq!(
        ids(db, "cpe_status").await,
        cpe_before,
        "cpe_status ids changed across down+up"
    );
    assert_eq!(
        child_pairs(db, "remediation_purl_status", "purl_status_id").await,
        rem_purl_before,
        "remediation_purl_status links changed across down+up"
    );
    assert_eq!(
        child_pairs(db, "remediation_product_status", "product_status_id").await,
        rem_product_before,
        "remediation_product_status links changed across down+up"
    );

    Ok(())
}

/// Columns of a `purl_status` row (other than `id`/`status_id`) that a crafted
/// duplicate must copy from the template so both rows recompute to the same id.
const PURL_COPY_COLS: &[&str] = &[
    "advisory_id",
    "vulnerability_id",
    "base_purl_id",
    "version_range_id",
    "context_cpe_id",
];

/// Everything the two `purl_status` duplicate-`fixed` tests need after reverting
/// to the status-table schema: the two `fixed` UUIDs, a real template row to
/// clone, the ingestor-computed collapsed id, and the advisory/vuln FKs for a
/// remediation child.
struct PurlDedupFixture {
    fixed_ids: Vec<Uuid>,
    template_id: Uuid,
    expected: Uuid,
    advisory_id: Uuid,
    vulnerability_id: String,
}

/// Reverts exactly m0002320 to the status-table schema and gathers a
/// [`PurlDedupFixture`]. The caller must have ingested a CSAF advisory first.
async fn purl_dedup_fixture(db: &Database) -> Result<PurlDedupFixture, anyhow::Error> {
    // Revert to the status-table schema so we can reference the two `fixed`
    // status UUIDs and write status_id-shaped rows the way the old code did.
    Migrator::down(db, Some(1)).await?;
    assert_status_table_restored(db).await;

    let fixed_ids = fixed_status_ids(db).await;
    assert_eq!(
        fixed_ids.len(),
        2,
        "the restored status seed must contain two distinct `fixed` rows"
    );

    // Borrow a real (non-`fixed`) purl_status row purely for its FK values, so
    // the crafted rows satisfy every foreign key.
    let template = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT ps.id, ps.base_purl_id, ps.version_range_id, ps.advisory_id, \
             ps.vulnerability_id, ps.context_cpe_id \
             FROM purl_status ps JOIN status s ON s.id = ps.status_id \
             WHERE s.slug <> 'fixed' LIMIT 1"
                .to_owned(),
        ))
        .await?
        .expect("ingested advisory should yield a non-`fixed` purl_status row");
    let template_id: Uuid = template.try_get("", "id")?;
    let base_purl_id: Uuid = template.try_get("", "base_purl_id")?;
    let version_range_id: Uuid = template.try_get("", "version_range_id")?;
    let advisory_id: Uuid = template.try_get("", "advisory_id")?;
    let vulnerability_id: String = template.try_get("", "vulnerability_id")?;
    let context_cpe_id: Option<Uuid> = template.try_get("", "context_cpe_id")?;

    // The id both crafted rows must collapse onto — computed by the ingestor's
    // own function, which is the behaviour the migration has to reproduce.
    let expected = purl_status_id(
        "fixed",
        base_purl_id,
        version_range_id,
        advisory_id,
        &vulnerability_id,
        context_cpe_id,
    );

    Ok(PurlDedupFixture {
        fixed_ids,
        template_id,
        expected,
        advisory_id,
        vulnerability_id,
    })
}

/// The pre-enum seed contained two different `fixed` status rows. After the
/// slug-based recompute, any two `purl_status` rows that differed only by which
/// `fixed` UUID they used collapse onto one id — as must their remediation
/// children. This crafts that exact collision and asserts the dedup keeps a
/// single survivor whose id matches the ingestor.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_dedupes_duplicate_fixed_purl_status(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Ingest real data so we have valid advisory/vulnerability/purl/version_range
    // parents (and an advisory_vulnerability row) to hang crafted rows off of.
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let db = &ctx.db;
    let f = purl_dedup_fixture(db).await?;

    assert_fixed_dedup(
        db,
        "purl_status",
        PURL_COPY_COLS,
        f.template_id,
        &f.fixed_ids,
        f.expected,
        Some(Child {
            table: "remediation_purl_status",
            fk_col: "purl_status_id",
            on: ChildOn::Both,
            advisory_id: f.advisory_id,
            vulnerability_id: f.vulnerability_id,
        }),
    )
    .await;

    Ok(())
}

/// A remediation child on the *loser* of a duplicate-`fixed` collision (not the
/// survivor) must be repointed to the survivor, not dropped with the loser
/// parent. `apply_remap` deletes a child only when a sibling child on a smaller
/// old id exists, so this lone-child case is the one that would silently lose
/// remediation data if that guard ever regressed — the symmetric
/// `recompute_dedupes_duplicate_fixed_purl_status` would not catch it.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_repoints_loser_only_remediation_child(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let db = &ctx.db;
    let f = purl_dedup_fixture(db).await?;

    assert_fixed_dedup(
        db,
        "purl_status",
        PURL_COPY_COLS,
        f.template_id,
        &f.fixed_ids,
        f.expected,
        Some(Child {
            table: "remediation_purl_status",
            fk_col: "purl_status_id",
            on: ChildOn::LoserOnly,
            advisory_id: f.advisory_id,
            vulnerability_id: f.vulnerability_id,
        }),
    )
    .await;

    Ok(())
}

/// Mirror of the purl test for `product_status` + `remediation_product_status`:
/// two rows that differ only by their `fixed` UUID collapse onto one id and their
/// remediation children dedup onto the survivor.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_dedupes_duplicate_fixed_product_status(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let db = &ctx.db;
    Migrator::down(db, Some(1)).await?;
    assert_status_table_restored(db).await;

    let fixed_ids = fixed_status_ids(db).await;
    assert_eq!(
        fixed_ids.len(),
        2,
        "expected two distinct `fixed` seed rows"
    );

    let template = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT ps.id, ps.product_version_range_id, ps.advisory_id, \
             ps.vulnerability_id, ps.context_cpe_id, ps.package \
             FROM product_status ps JOIN status s ON s.id = ps.status_id \
             WHERE s.slug <> 'fixed' LIMIT 1"
                .to_owned(),
        ))
        .await?
        .expect("ingested advisory should yield a non-`fixed` product_status row");
    let template_id: Uuid = template.try_get("", "id")?;
    let product_version_range_id: Uuid = template.try_get("", "product_version_range_id")?;
    let advisory_id: Uuid = template.try_get("", "advisory_id")?;
    let vulnerability_id: String = template.try_get("", "vulnerability_id")?;
    let context_cpe_id: Option<Uuid> = template.try_get("", "context_cpe_id")?;
    let package: Option<String> = template.try_get("", "package")?;

    let expected = product_status_id(
        "fixed",
        product_version_range_id,
        advisory_id,
        &vulnerability_id,
        context_cpe_id,
        package.as_deref(),
    );

    assert_fixed_dedup(
        db,
        "product_status",
        &[
            "advisory_id",
            "vulnerability_id",
            "package",
            "product_version_range_id",
            "context_cpe_id",
            "csaf_product_ids",
        ],
        template_id,
        &fixed_ids,
        expected,
        Some(Child {
            table: "remediation_product_status",
            fk_col: "product_status_id",
            on: ChildOn::Both,
            advisory_id,
            vulnerability_id,
        }),
    )
    .await;

    Ok(())
}

/// Reverts to the status-table schema, crafts a duplicate-`fixed` `product_status`
/// collision whose two rows differ only in `csaf_product_ids` — the one non-hashed
/// column — given as SQL array expressions (`survivor_arr` on the surviving `u(1)`,
/// `loser_arr` on the discarded `u(2)`, each e.g. `"ARRAY['prod-b','prod-a']"` or
/// the literal `"NULL"`), plus one *non-colliding* marker row carrying an
/// intentionally unsorted array. It runs `up(1)` and asserts:
///
/// * exactly one row disappears — the two crafted `fixed` rows really collapsed
///   onto a single survivor (not, say, only one of them having been inserted);
/// * the survivor's `csaf_product_ids` equals `expected_union` — `Some(sorted
///   DISTINCT union)` so nothing the loser held is dropped, or `None` when both
///   colliding rows were empty (an all-empty group must stay `NULL`, never become a
///   corrupt `{NULL}`); and
/// * the marker row's array is left byte-for-byte untouched — the union is
///   restricted to genuine collisions and must not sort/dedup every row.
///
/// The caller must have ingested a CSAF advisory first (for real FK parents).
async fn assert_csaf_union(
    db: &Database,
    survivor_arr: &str,
    loser_arr: &str,
    expected_union: Option<&[&str]>,
) -> Result<(), anyhow::Error> {
    Migrator::down(db, Some(1)).await?;
    assert_status_table_restored(db).await;

    let fixed_ids = fixed_status_ids(db).await;
    assert_eq!(
        fixed_ids.len(),
        2,
        "expected two distinct `fixed` seed rows"
    );

    // A real non-`fixed` row to clone FK/hash-input columns (and its status) from.
    let template = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT ps.id, ps.product_version_range_id, ps.advisory_id, \
             ps.vulnerability_id, ps.context_cpe_id, ps.package, s.slug \
             FROM product_status ps JOIN status s ON s.id = ps.status_id \
             WHERE s.slug <> 'fixed' LIMIT 1"
                .to_owned(),
        ))
        .await?
        .expect("ingested advisory should yield a non-`fixed` product_status row");
    let template_id: Uuid = template.try_get("", "id")?;
    let product_version_range_id: Uuid = template.try_get("", "product_version_range_id")?;
    let advisory_id: Uuid = template.try_get("", "advisory_id")?;
    let vulnerability_id: String = template.try_get("", "vulnerability_id")?;
    let context_cpe_id: Option<Uuid> = template.try_get("", "context_cpe_id")?;
    let package: Option<String> = template.try_get("", "package")?;
    let slug: String = template.try_get("", "slug")?;

    // The id both crafted `fixed` rows collapse onto.
    let expected = product_status_id(
        "fixed",
        product_version_range_id,
        advisory_id,
        &vulnerability_id,
        context_cpe_id,
        package.as_deref(),
    );

    // A non-colliding control row: identical hash inputs to the template except a
    // unique `package`, so it recomputes to its own singleton id and is never part
    // of a collision group. Its unsorted, deliberately unordered array must come
    // back exactly as written — proving the union leaves non-colliding rows alone.
    // A merge that dropped the `HAVING count(*) > 1` guard would rewrite (sort and
    // dedup) every row and turn this into `['aaa','zzz']`.
    let marker_pkg = "csaf-union-untouched-marker";
    let untouched_id = product_status_id(
        &slug,
        product_version_range_id,
        advisory_id,
        &vulnerability_id,
        context_cpe_id,
        Some(marker_pkg),
    );

    // Two `fixed` rows sharing every hash input (cloned from the template) but each
    // with a distinct `fixed` UUID and the given csaf_product_ids. u(1) is the
    // smallest old id, so `mark_survivors` keeps it; u(2) is the loser.
    for (row_id, fixed_id, arr) in [
        (u(1), fixed_ids[0], survivor_arr),
        (u(2), fixed_ids[1], loser_arr),
    ] {
        db.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            format!(
                "INSERT INTO product_status \
                 (id, status_id, advisory_id, vulnerability_id, package, \
                  product_version_range_id, context_cpe_id, csaf_product_ids) \
                 SELECT $1, $2, advisory_id, vulnerability_id, package, \
                  product_version_range_id, context_cpe_id, {arr}::text[] \
                 FROM product_status WHERE id = $3"
            ),
            [row_id.into(), fixed_id.into(), template_id.into()],
        ))
        .await?;
    }

    // The non-colliding marker row (keeps the template's non-`fixed` status_id).
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        "INSERT INTO product_status \
         (id, status_id, advisory_id, vulnerability_id, package, \
          product_version_range_id, context_cpe_id, csaf_product_ids) \
         SELECT $1, status_id, advisory_id, vulnerability_id, $2, \
          product_version_range_id, context_cpe_id, ARRAY['zzz','aaa']::text[] \
         FROM product_status WHERE id = $3"
            .to_owned(),
        [
            u(3).into(),
            marker_pkg.to_owned().into(),
            template_id.into(),
        ],
    ))
    .await?;

    // Neither recomputed id may pre-exist, or its assertion would be moot.
    for (id, what) in [(expected, "collapsed survivor"), (untouched_id, "marker")] {
        assert_eq!(
            count(
                db,
                Statement::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    "SELECT count(*) AS n FROM product_status WHERE id = $1".to_owned(),
                    [id.into()],
                ),
            )
            .await,
            0,
            "the {what} id must not pre-exist before the recompute"
        );
    }

    // The three crafted rows must all be present, so the collapse below is
    // guaranteed to act on the shape we built. Without this, a future refactor that
    // inserted only the loser could leave a lone singleton keeping the loser's
    // values and pass the survivor assertion vacuously (mirrors `assert_fixed_dedup`).
    assert_eq!(
        count(
            db,
            Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                "SELECT count(*) AS n FROM product_status WHERE id IN ($1, $2, $3)".to_owned(),
                [u(1).into(), u(2).into(), u(3).into()],
            ),
        )
        .await,
        3,
        "expected the two colliding rows plus the marker row before the recompute"
    );

    // Total rows before the collapse, so we can prove exactly one (the collapsed
    // `fixed` duplicate) disappears — the marker and every ingested row survive.
    let parents_before = count(
        db,
        Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT count(*) AS n FROM product_status".to_owned(),
        ),
    )
    .await;

    Migrator::up(db, Some(1)).await?;

    assert_eq!(
        count(
            db,
            Statement::from_string(
                DatabaseBackend::Postgres,
                "SELECT count(*) AS n FROM product_status".to_owned(),
            ),
        )
        .await,
        parents_before - 1,
        "exactly one product_status row (the collapsed `fixed` duplicate) should \
         disappear; a different delta means the crafted rows did not collapse onto \
         one survivor"
    );

    // Read the survivor as nullable: an all-empty collision must leave it `NULL`
    // (not a corrupt `{NULL}`), and a NULL that should have inherited the loser's
    // values then fails the assert with a clear message instead of a deserialize
    // error.
    let merged: Option<Vec<String>> = db
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT csaf_product_ids AS ids FROM product_status WHERE id = $1".to_owned(),
            [expected.into()],
        ))
        .await?
        .expect("the collapsed survivor row should exist")
        .try_get::<Option<Vec<String>>>("", "ids")?;
    let expected_union: Option<Vec<String>> =
        expected_union.map(|v| v.iter().map(|s| s.to_string()).collect());
    assert_eq!(
        merged, expected_union,
        "survivor's csaf_product_ids should equal the sorted DISTINCT union of the \
         colliding rows (NULL only when both are empty; the loser's values must \
         never be lost)"
    );

    let untouched: Vec<String> = db
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT csaf_product_ids AS ids FROM product_status WHERE id = $1".to_owned(),
            [untouched_id.into()],
        ))
        .await?
        .expect("the non-colliding marker row should survive the recompute")
        .try_get::<Vec<String>>("", "ids")?;
    assert_eq!(
        untouched,
        vec!["zzz".to_owned(), "aaa".to_owned()],
        "a non-colliding row's csaf_product_ids must be left byte-for-byte \
         untouched (not sorted or deduped) by the collision-only union"
    );

    Ok(())
}

/// `csaf_product_ids` is a `product_status` column that is **not** part of the id
/// hash, so two rows that collapse in the duplicate-`fixed` dedup can legitimately
/// hold different values there. The migration must union them into the survivor
/// instead of dropping the loser's with the deleted row. The survivor's array is
/// crafted deliberately unsorted, so only an `ORDER BY` union produces the expected
/// `[prod-a, prod-b, prod-c]` — a concat-without-sort merge would fail here.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_unions_csaf_product_ids_on_collapse(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    // Survivor u(1) holds {prod-b, prod-a} (unsorted); loser u(2) holds
    // {prod-b, prod-c}. The shared 'prod-b' is deduped, the loser's 'prod-c' is
    // preserved, and the result comes back sorted.
    assert_csaf_union(
        &ctx.db,
        "ARRAY['prod-b','prod-a']",
        "ARRAY['prod-b','prod-c']",
        Some(&["prod-a", "prod-b", "prod-c"]),
    )
    .await
}

/// The survivor of a collapse may itself hold `NULL`/no `csaf_product_ids` while
/// the deleted loser carries the only values — a real production shape (the CSAF
/// creator emits `None` when a product resolves no ids). The survivor must inherit
/// the loser's values rather than keep its own `NULL`. This is the unique guard for
/// a refactor that still sorts and dedups but sources the values from
/// `survivor.col || loser.col` instead of unnesting the whole collision group:
/// `NULL || anything` is `NULL` in Postgres, so only this NULL-survivor shape would
/// regress — `recompute_unions_csaf_product_ids_on_collapse` (both rows non-NULL)
/// still passes.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_unions_csaf_product_ids_into_null_survivor(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    // Survivor u(1) holds NULL; loser u(2) holds {prod-a, prod-b}. The survivor
    // must end up with the loser's values instead of staying NULL.
    assert_csaf_union(
        &ctx.db,
        "NULL",
        "ARRAY['prod-a','prod-b']",
        Some(&["prod-a", "prod-b"]),
    )
    .await
}

/// When *both* colliding rows carry `NULL`/no `csaf_product_ids`, the survivor must
/// stay `NULL` — the "all-empty group is left untouched" contract the migration's
/// union SQL documents. That relies on `CROSS JOIN LATERAL unnest` dropping the
/// empty group out of the aggregate; a `LEFT JOIN LATERAL` (or any coalescing)
/// refactor would instead write a corrupt single-element `{NULL}` array. Because
/// `csaf_product_ids` is not a hash input, such corruption changes no id and would
/// slip past every other test — this is the only one that would catch it.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_leaves_all_null_csaf_product_ids_null(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    // Both crafted rows hold NULL; the collapsed survivor must remain NULL.
    assert_csaf_union(&ctx.db, "NULL", "NULL", None).await
}

/// `cpe_status` has no remediation child, but the same duplicate-`fixed` collapse
/// still applies to its parents: two rows differing only by their `fixed` UUID
/// must dedup onto one recomputed id.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recompute_collapses_duplicate_fixed_cpe_status(
    ctx: TrustifyContext,
) -> Result<(), anyhow::Error> {
    // A CVE advisory populates cpe_status.
    ctx.ingest_document("cve/CVE-2099-0001.json").await?;

    let db = &ctx.db;
    Migrator::down(db, Some(1)).await?;
    assert_status_table_restored(db).await;

    let fixed_ids = fixed_status_ids(db).await;
    assert_eq!(
        fixed_ids.len(),
        2,
        "expected two distinct `fixed` seed rows"
    );

    let template = db
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SELECT cs.id, cs.cpe_id, cs.version_range_id, cs.advisory_id, \
             cs.vulnerability_id, cs.context_cpe_id \
             FROM cpe_status cs JOIN status s ON s.id = cs.status_id \
             WHERE s.slug <> 'fixed' LIMIT 1"
                .to_owned(),
        ))
        .await?
        .expect("ingested advisory should yield a non-`fixed` cpe_status row");
    let template_id: Uuid = template.try_get("", "id")?;
    let cpe_id: Uuid = template.try_get("", "cpe_id")?;
    let version_range_id: Uuid = template.try_get("", "version_range_id")?;
    let advisory_id: Uuid = template.try_get("", "advisory_id")?;
    let vulnerability_id: String = template.try_get("", "vulnerability_id")?;
    let context_cpe_id: Option<Uuid> = template.try_get("", "context_cpe_id")?;

    let expected = cpe_status_id(
        "fixed",
        cpe_id,
        version_range_id,
        advisory_id,
        &vulnerability_id,
        context_cpe_id,
    );

    assert_fixed_dedup(
        db,
        "cpe_status",
        &[
            "advisory_id",
            "vulnerability_id",
            "cpe_id",
            "version_range_id",
            "context_cpe_id",
        ],
        template_id,
        &fixed_ids,
        expected,
        None,
    )
    .await;

    Ok(())
}
