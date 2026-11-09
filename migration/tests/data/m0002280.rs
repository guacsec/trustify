use migration::{
    Migrator,
    data::{Database, Direction, Runner},
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::Value;
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

/// The suppliers of all SBOMs.
async fn suppliers(ctx: &TrustifyContext) -> anyhow::Result<Value> {
    let row = ctx
        .db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT coalesce(jsonb_agg(suppliers ORDER BY sbom_id), '[]'::jsonb) AS rows FROM sbom",
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no result"))?;
    Ok(row.try_get("", "rows")?)
}

/// An SPDX SBOM which only parses with its invalid license expressions replaced gets its suppliers
/// too.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn invalid_license(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    let fresh = suppliers(ctx).await?;
    ctx.db
        .execute_unprepared("UPDATE sbom SET suppliers = '{}'")
        .await?;

    Runner {
        database: Database::Provided(ctx.db.clone().into_connection()),
        storage: ctx.storage.clone().into(),
        direction: Direction::Up,
        migrations: vec!["m0002280_backfill_sbom_suppliers".into()],
        options: Default::default(),
    }
    .run::<Migrator>()
    .await?;

    assert_eq!(
        (suppliers(ctx).await?, fresh),
        (
            serde_json::json!([["Organization: Red Hat"]]),
            serde_json::json!([["Organization: Red Hat"]])
        )
    );
    Ok(())
}
