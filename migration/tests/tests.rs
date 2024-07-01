use migration::{Migrator, MigratorTrait};
use test_context::test_context;
use test_log::test;
use trustify_common::db::test::TrustifyContext;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_migrations(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    let migrations = Migrator::get_applied_migrations(&db).await?;
    // 'Migrator.up' was called in bootstrap function when using TrustifyContext.
    // At this point we already have migrations.
    assert!(migrations.len() > 1);

    db.refresh().await?;

    let rolled_back_and_reapplied_migrations = Migrator::get_applied_migrations(&db).await?;
    assert!(rolled_back_and_reapplied_migrations.len() > 1);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn only_up_migration(_ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    Ok(())
}
