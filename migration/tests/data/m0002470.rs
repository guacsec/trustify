use migration::{
    Migrator,
    data::{Database, Direction, Runner},
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

/// Count rows of a query returning a single `count(*)` column named `c`.
async fn count(ctx: &TrustifyContext, sql: &str) -> anyhow::Result<i64> {
    let row = ctx
        .db
        .query_one(Statement::from_string(DbBackend::Postgres, sql))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no result"))?;
    Ok(row.try_get("", "c")?)
}

/// The affected ranges derived from Red Hat's fixed versions by older versions are removed, the
/// stated statuses are kept, and the publisher namespace is backfilled.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn drop_redhat_derived(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;

    // simulate the state of older versions: no namespace, and derived "affected" ranges
    ctx.db
        .execute_unprepared(
            r#"
UPDATE advisory SET publisher_namespace = NULL;

INSERT INTO version_range (id, version_scheme_id, low_version, low_inclusive, high_version, high_inclusive)
SELECT gen_random_uuid(), vr.version_scheme_id, NULL, false, vr.low_version, false
FROM purl_status ps JOIN version_range vr ON vr.id = ps.version_range_id;

-- derived: no lower bound, exclusive upper bound equal to the fixed version
INSERT INTO purl_status (id, advisory_id, vulnerability_id, status_id, base_purl_id, version_range_id)
SELECT gen_random_uuid(), ps.advisory_id, ps.vulnerability_id, (SELECT id FROM status WHERE slug = 'affected'), ps.base_purl_id, dvr.id
FROM purl_status ps
JOIN version_range vr ON vr.id = ps.version_range_id
JOIN version_range dvr ON dvr.low_version IS NULL AND dvr.high_version = vr.low_version AND dvr.version_scheme_id = vr.version_scheme_id;
"#,
        )
        .await?;

    let affected = "SELECT count(*) AS c FROM purl_status ps JOIN status s ON s.id = ps.status_id WHERE s.slug = 'affected'";
    let fixed = "SELECT count(*) AS c FROM purl_status ps JOIN status s ON s.id = ps.status_id WHERE s.slug = 'fixed'";
    let fixed_before = count(ctx, fixed).await?;
    assert!(fixed_before > 0);
    assert!(count(ctx, affected).await? > 0);

    Runner {
        database: Database::Provided(ctx.db.clone().into_connection()),
        storage: ctx.storage.clone().into(),
        direction: Direction::Up,
        migrations: vec!["m0002470_drop_redhat_derived_purl_status".into()],
        options: Default::default(),
    }
    .run::<Migrator>()
    .await?;

    assert_eq!(count(ctx, affected).await?, 0);
    assert_eq!(count(ctx, fixed).await?, fixed_before);
    assert_eq!(
        count(
            ctx,
            "SELECT count(*) AS c FROM advisory WHERE publisher_namespace = 'https://www.redhat.com'"
        )
        .await?,
        1
    );

    Ok(())
}
