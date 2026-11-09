use migration::{
    Migrator, MigratorTraitSelf,
    data::{Database, Direction, Options, Runner},
};
use rstest::rstest;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

const MIGRATION: &str = "m0002710_backfill_advisory_assertions";

const ADVISORIES: &str = "(SELECT id, publisher_namespace FROM advisory)";

/// Scores without their ID, which is random.
const SCORES: &str = "(SELECT advisory_id, vulnerability_id, type, vector, score, severity FROM advisory_vulnerability_score)";

/// All rows the migration may write.
const TABLES: &[&str] = &[
    ADVISORIES,
    "advisory_vulnerability_cpe",
    "advisory_vulnerability_hash",
    "advisory_vulnerability_product_identifier",
    SCORES,
    "advisory_vulnerability_upstream",
    "assertion_context",
    "assertion_context_identifier",
    "cpe_status",
    "product_status",
    "purl_status",
    "remediation",
    "remediation_cpe_assertion",
    "remediation_hash_assertion",
    "remediation_product_identifier_assertion",
    "remediation_product_status",
    "remediation_purl_status",
];

/// The rows of all tables, sorted.
async fn rows(ctx: &TrustifyContext) -> anyhow::Result<Value> {
    let mut result = serde_json::Map::new();
    for table in TABLES {
        let row = ctx
            .db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT coalesce(jsonb_agg(t ORDER BY t::text), '[]'::jsonb) AS rows FROM {table} t"
                ),
            ))
            .await?
            .ok_or_else(|| anyhow::anyhow!("no result"))?;
        result.insert(table.to_string(), row.try_get("", "rows")?);
    }
    Ok(Value::Object(result))
}

/// A single number.
async fn number(ctx: &TrustifyContext, sql: &str) -> anyhow::Result<i64> {
    let row = ctx
        .db
        .query_one_raw(Statement::from_string(DbBackend::Postgres, sql))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no result"))?;
    Ok(row.try_get("", "n")?)
}

/// The state around the statements: queued advisories, extraction revision, verdict revision.
async fn state(ctx: &TrustifyContext) -> anyhow::Result<[i64; 3]> {
    Ok([
        number(
            ctx,
            "SELECT count(*) AS n FROM correlation_extraction_queue WHERE entity_type = 'advisory'",
        )
        .await?,
        number(
            ctx,
            "SELECT revision AS n FROM correlation_extraction_revision",
        )
        .await?,
        number(
            ctx,
            "SELECT revision AS n FROM correlation_verdict_revision",
        )
        .await?,
    ])
}

async fn run(ctx: &TrustifyContext, options: Options) -> anyhow::Result<()> {
    Runner {
        database: Database::Provided(ctx.db.clone().into_connection()),
        storage: ctx.storage.clone().into(),
        direction: Direction::Up,
        migrations: vec![MIGRATION.into()],
        options,
    }
    .run::<Migrator>()
    .await
}

/// Mark what's ingested so far as ingested before the statement migrations.
async fn make_older(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.db
        .execute_unprepared(
            r#"
UPDATE seaql_migrations SET applied_at = extract(epoch FROM now())::bigint
    WHERE version = 'm0002580_remediation_assertions';
UPDATE source_document SET ingested = now() - interval '1 day';
"#,
        )
        .await?;
    Ok(())
}

/// What older versions stored of what the current version stores.
async fn downgrade_statements(ctx: &TrustifyContext) -> anyhow::Result<()> {
    make_older(ctx).await?;
    ctx.db
        .execute_unprepared(
            r#"
UPDATE advisory SET publisher_namespace = NULL;
DELETE FROM advisory_vulnerability_cpe;
DELETE FROM advisory_vulnerability_hash;
DELETE FROM advisory_vulnerability_product_identifier;
-- m0002010 skipped OSV records stored as YAML
DELETE FROM advisory_vulnerability_score;
DELETE FROM advisory_vulnerability_upstream;
-- older versions wrote different rows: these must go, not stay next to the new ones
UPDATE cpe_status SET id = gen_random_uuid(), status_id = (SELECT id FROM status WHERE slug = 'under_investigation');
DELETE FROM product_status;
DELETE FROM remediation;
UPDATE purl_status SET id = gen_random_uuid(), qualified_purl_id = NULL,
    assertion_context_id = NULL, is_default = false, source_provider = NULL;
DELETE FROM assertion_context;
"#,
        )
        .await?;
    Ok(())
}

/// An advisory ingested by older versions ends up with the rows of a fresh ingest, and running it
/// again doesn't change them.
#[test_context(TrustifyContext)]
#[rstest]
#[case::csaf_vex("correlation/cve-2024-34155.json.xz")]
#[case::csaf_rhsa("csaf/rhsa-2024_3666.json")]
#[case::csaf_hashes("scenarios/S18_digest_correlation/vex/vde-2025-106.json")]
#[case::csaf_product_identifiers("scenarios/S19_sku_correlation/vex/hbsa-2025-0002.json")]
#[case::cve_applicability("scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json")]
#[case::cve_defaults("scenarios/S7_cpeonly_node_hummingbird/cve/CVE-2026-12151.json")]
#[case::nvd("nvd/CVE-2024-6387.json")]
#[case::osv_upstream("osv/DSA-5790-1.json")]
#[case::osv_ranges("osv/GHSA-qq9f-q439-2574.json")]
#[case::osv_yaml_pysec("osv/PYSEC-2024-55.yaml")]
#[case::osv_yaml_rsec("osv/RSEC-2023-6.yaml")]
#[test_log::test(tokio::test)]
async fn same_as_fresh_ingest(ctx: &TrustifyContext, #[case] document: &str) -> anyhow::Result<()> {
    ctx.ingest_document(document).await?;
    let fresh = rows(ctx).await?;
    let [queued, extraction, verdict] = state(ctx).await?;
    assert_eq!(queued, 1);

    downgrade_statements(ctx).await?;
    assert_ne!(rows(ctx).await?, fresh);
    let verdict = verdict.max(state(ctx).await?[2]);

    run(ctx, Options::default()).await?;
    assert_eq!(rows(ctx).await?, fresh);
    assert_eq!(state(ctx).await?, [0, extraction + 1, verdict + 1]);

    run(ctx, Options::default()).await?;
    assert_eq!(rows(ctx).await?, fresh);
    Ok(())
}

/// A database with only later CVE and OSV records doesn't do any work.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn later_advisories_stay_untouched(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("scenarios/S7_cpeonly_node_hummingbird/cve/CVE-2026-12151.json")
        .await?;
    ctx.ingest_document("osv/DSA-5790-1.json").await?;
    downgrade_statements(ctx).await?;
    ctx.db
        .execute_unprepared(
            "UPDATE seaql_migrations SET applied_at = extract(epoch FROM now() - interval '2 days')::bigint \
             WHERE version = 'm0002580_remediation_assertions'",
        )
        .await?;
    let before = (rows(ctx).await?, state(ctx).await?);

    run(ctx, Options::default()).await?;

    assert_eq!((rows(ctx).await?, state(ctx).await?), before);
    Ok(())
}

/// A later CSAF advisory gets the CSAF product IDs ingestion used to drop.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn later_csaf_gets_all_product_ids(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    let fresh = rows(ctx).await?;
    ctx.db
        .execute_unprepared(
            r#"
UPDATE product_status SET csaf_product_ids = csaf_product_ids[1:1];
UPDATE seaql_migrations SET applied_at = extract(epoch FROM now() - interval '2 days')::bigint
    WHERE version = 'm0002580_remediation_assertions';
"#,
        )
        .await?;
    assert_ne!(rows(ctx).await?, fresh);

    run(ctx, Options::default()).await?;

    assert_eq!(rows(ctx).await?, fresh);
    Ok(())
}

/// Skipping the data part leaves everything for a later run, including the queue and revisions.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn skipped_until_later_run(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    let fresh = rows(ctx).await?;
    downgrade_statements(ctx).await?;
    let before = (rows(ctx).await?, state(ctx).await?);

    let skip = Options {
        skip: vec![MIGRATION.into()],
        ..Default::default()
    };
    run(ctx, skip).await?;
    assert_eq!((rows(ctx).await?, state(ctx).await?), before);

    run(ctx, Options::default()).await?;
    assert_eq!(rows(ctx).await?, fresh);
    Ok(())
}

/// An advisory added afterwards is queued as usual.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn later_advisory_is_queued(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    downgrade_statements(ctx).await?;
    run(ctx, Options::default()).await?;
    assert_eq!(state(ctx).await?[0], 0);

    ctx.ingest_document("osv/DSA-5790-1.json").await?;

    assert_eq!(state(ctx).await?[0], 1);
    Ok(())
}

/// A vulnerability which older versions didn't link doesn't stop the statements of the others.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn missing_link_is_created(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("osv/GHSA-qq9f-q439-2574.json").await?;
    let fresh = rows(ctx).await?;
    downgrade_statements(ctx).await?;
    ctx.db
        .execute_unprepared(
            "DELETE FROM purl_status; DELETE FROM advisory_vulnerability_score; \
             DELETE FROM advisory_vulnerability;",
        )
        .await?;

    run(ctx, Options::default()).await?;

    assert_eq!(rows(ctx).await?, fresh);
    Ok(())
}

/// The ranges older versions derived from the fixed versions of Red Hat advisories are removed,
/// and the publisher namespace is backfilled.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn drop_redhat_derived(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    let fresh = rows(ctx).await?;
    downgrade_statements(ctx).await?;

    // derived: no lower bound, exclusive upper bound equal to the fixed version
    ctx.db
        .execute_unprepared(
            r#"
INSERT INTO version_range (id, version_scheme_id, low_version, low_inclusive, high_version, high_inclusive)
SELECT gen_random_uuid(), vr.version_scheme_id, NULL, false, vr.low_version, false
FROM purl_status ps JOIN version_range vr ON vr.id = ps.version_range_id;

INSERT INTO purl_status (id, advisory_id, vulnerability_id, status_id, base_purl_id, version_range_id)
SELECT gen_random_uuid(), ps.advisory_id, ps.vulnerability_id, (SELECT id FROM status WHERE slug = 'affected'), ps.base_purl_id, dvr.id
FROM purl_status ps
JOIN version_range vr ON vr.id = ps.version_range_id
JOIN version_range dvr ON dvr.low_version IS NULL AND dvr.high_version = vr.low_version AND dvr.version_scheme_id = vr.version_scheme_id;
"#,
        )
        .await?;
    let affected = "SELECT count(*) AS n FROM purl_status ps JOIN status s ON s.id = ps.status_id WHERE s.slug = 'affected'";
    assert!(number(ctx, affected).await? > 0);

    run(ctx, Options::default()).await?;

    assert_eq!(number(ctx, affected).await?, 0);
    let result = rows(ctx).await?;
    assert_eq!(result, fresh);
    assert_eq!(
        result[ADVISORIES][0]["publisher_namespace"],
        json!("https://www.redhat.com")
    );
    Ok(())
}

/// A document which can't be parsed fails the migration, as its statements would stay wrong.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn unknown_format_fails(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    ctx.ingest_document("spdx/simple.json").await?;
    make_older(ctx).await?;
    ctx.db
        .execute_unprepared(
            "UPDATE advisory SET source_document_id = \
             (SELECT source_document_id FROM sbom LIMIT 1)",
        )
        .await?;

    let err = run(ctx, Options::default()).await.unwrap_err();

    assert!(
        err.to_string().contains("Unable to parse source document"),
        "{err}"
    );
    Ok(())
}

/// A document which is missing fails the migration.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn missing_document_fails(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    make_older(ctx).await?;
    ctx.db
        .execute_unprepared("UPDATE source_document SET sha256 = repeat('0', 64)")
        .await?;
    let before = state(ctx).await?;

    let err = run(ctx, Options::default()).await.unwrap_err();

    assert!(
        err.to_string().contains("Failed to load source document"),
        "{err}"
    );
    assert_eq!(state(ctx).await?, before);
    Ok(())
}

/// Running it before the schema migrations fails, instead of succeeding without any work.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn before_schema_migrations_fails(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.db
        .execute_unprepared(
            "DELETE FROM seaql_migrations WHERE version = 'm0002580_remediation_assertions'",
        )
        .await?;

    let err = run(ctx, Options::default()).await.unwrap_err();

    assert!(err.to_string().contains("must run first"), "{err}");
    Ok(())
}

/// Documents sharing rows (PURLs, versions, organizations) can be processed at the same time.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn several_documents_in_parallel(ctx: &TrustifyContext) -> anyhow::Result<()> {
    for document in [
        "correlation/cve-2024-34155.json.xz",
        "csaf/rhsa-2024_3666.json",
        "scenarios/S19_sku_correlation/vex/hbsa-2025-0002.json",
        "scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json",
        "scenarios/S26_cve_cpe_applicability_kernel/cve/CVE-2024-26581.json",
        "osv/DSA-5790-1.json",
        "osv/GHSA-qq9f-q439-2574.json",
        "osv/PYSEC-2024-55.yaml",
    ] {
        ctx.ingest_document(document).await?;
    }
    let fresh = rows(ctx).await?;
    downgrade_statements(ctx).await?;

    run(
        ctx,
        Options {
            concurrent: 8,
            ..Default::default()
        },
    )
    .await?;

    assert_eq!(rows(ctx).await?, fresh);
    Ok(())
}

/// As part of the regular migrations, which run it in one transaction, one document at a time.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn during_regular_migrations(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    ctx.ingest_document("osv/DSA-5790-1.json").await?;
    let fresh = rows(ctx).await?;
    let [_, extraction, _] = state(ctx).await?;

    let migrator = Migrator::new(ctx.storage.clone(), ());
    migrator.down(&ctx.db, Some(1)).await?;
    downgrade_statements(ctx).await?;
    migrator.up(&ctx.db, Some(1)).await?;

    assert_eq!(rows(ctx).await?, fresh);
    assert_eq!(state(ctx).await?[..2], [0, extraction + 1]);
    Ok(())
}
