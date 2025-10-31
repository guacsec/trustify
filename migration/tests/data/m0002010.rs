use crate::MigratorTest;
use migration::Migrator;
use migration::data::{Database, Direction, MigrationWithData, Options, Runner};
use sea_orm_migration::MigratorTrait;
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyMigrationContext, commit, ctx::DumpId};

commit!(Commit("8c6ad23172e66a6c923dcc8f702e6125a8d48723"));

#[test_context(TrustifyMigrationContext<Commit>)]
#[test(tokio::test)]
async fn examples(
    ctx: &TrustifyMigrationContext<Commit>, /* commit previous to this PR */
) -> Result<(), anyhow::Error> {
    let migrations = vec!["m0002010_add_advisory_scores".into()];

    // first run the data migration
    Runner {
        direction: Direction::Up,
        storage: ctx.storage.clone().into(),
        migrations: migrations.clone(),
        database: Database::Provided(ctx.db.clone().into_connection()),
        options: Default::default(),
    }
    .run::<Migrator>()
    .await?;

    // now run the migrations, but skip the already run migration

    MigrationWithData::run_with_test(
        ctx.storage.clone(),
        Options {
            skip: migrations,
            ..Default::default()
        },
        async { MigratorTest::up(&ctx.db, None).await },
    )
    .await?;

    // done

    Ok(())
}
