use migration::{
    Migrator,
    data::{Database, Direction, MigrationWithData, Options, Runner},
};
use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::MigratorTrait;
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyMigrationContext, commit};

use crate::MigratorTest;

// Same pre-m0002010 commit used by m0002010.rs tests
commit!(PreScores("6d3ea814b4b44fe16ea8f21724dda5abb0fc7932"));

/// Verify the full score pipeline: m0002010 populates advisory_vulnerability_score
/// using the vector-string parser, then m0002250 backfills vulnerability.base_score.
#[test_context(TrustifyMigrationContext<PreScores>)]
#[test(tokio::test)]
async fn backfill_vulnerability_base_score(
    ctx: &TrustifyMigrationContext<PreScores>,
) -> Result<(), anyhow::Error> {
    let data_migrations = vec!["m0002010_add_advisory_scores".into()];

    // Run the data migration with the current (fixed) code
    Runner {
        direction: Direction::Up,
        storage: ctx.storage.clone().into(),
        migrations: data_migrations.clone(),
        database: Database::Provided(ctx.db.clone().into_connection()),
        options: Default::default(),
    }
    .run::<Migrator>()
    .await?;

    // Run all remaining schema migrations (including m0002250), skipping the
    // already-applied data migration
    MigrationWithData::run_with_test(
        ctx.storage.clone(),
        Options {
            skip: data_migrations,
            ..Default::default()
        },
        async { MigratorTest::up(&ctx.db, None).await },
    )
    .await?;

    // After m0002250: every vulnerability whose authoritative advisory has scores
    // in advisory_vulnerability_score must have base_score populated.
    let missing = ctx
        .db
        .query_all(Statement::from_string(
            ctx.db.get_database_backend(),
            r#"
SELECT v.id
FROM vulnerability v
JOIN advisory_vulnerability_score avs
    ON avs.advisory_id = v.authoritative_advisory_id
    AND avs.vulnerability_id = v.id
WHERE v.base_score IS NULL
"#,
        ))
        .await?;

    assert!(
        missing.is_empty(),
        "expected all vulnerabilities with authoritative scores to have base_score populated, \
         but {} still have NULL",
        missing.len()
    );

    Ok(())
}
