use test_context::test_context;
use test_log::test;
use trustify_db::Database;
use trustify_test_context::TrustifyMigrationContext;

/// test to see if we can import a dump from a previous commit and migrate, including the data
#[test_context(TrustifyMigrationContext)]
#[test(tokio::test)]
async fn from_previous(ctx: &TrustifyMigrationContext) -> Result<(), anyhow::Error> {
    // We automatically start with a database imported from the previous commit.
    // But we haven't migrated to the most recent schema so far. That's done by the next step.

    Database(&ctx.db).migrate().await?;

    Ok(())
}
