#![recursion_limit = "256"]
use migration::{Migrator, MigratorTraitSelf, data::Options};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

/// A migrator for testing other migrations, leaving out the backfill which would run on their way
/// back up.
fn without_backfill(ctx: &TrustifyContext) -> Migrator {
    Migrator::new(
        ctx.storage.clone(),
        Options {
            skip: vec!["m0002710_backfill_advisory_assertions".into()],
            ..Default::default()
        },
    )
}

/// The number of applied migrations from the named one on, to roll back to just before it (and
/// re-apply them), independent of migrations added later.
async fn since(
    migrator: &Migrator,
    db: &sea_orm::DatabaseConnection,
    name: &str,
) -> anyhow::Result<u32> {
    let names = migrator
        .get_applied_migrations(db)
        .await?
        .iter()
        .map(|migration| migration.name().to_string())
        .collect::<Vec<_>>();
    let position = names
        .iter()
        .position(|applied| applied == name)
        .ok_or_else(|| anyhow::anyhow!("migration {name} is not applied"))?;
    Ok(u32::try_from(names.len() - position)?)
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn test_migrations(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = &ctx.db;
    let migrator = Migrator::new(ctx.storage.clone(), ());

    let migrations = migrator.get_applied_migrations(db).await?;
    // 'Migrator.up' was called in bootstrap function when using TrustifyContext.
    // At this point we already have migrations.
    assert!(!migrations.is_empty());

    trustify_db::Database(db).refresh(&migrator).await?;

    let rolled_back_and_reapplied_migrations = migrator.get_applied_migrations(db).await?;
    assert!(!rolled_back_and_reapplied_migrations.is_empty());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn only_up_migration(_ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    // The initialization of the database will already call the `up` function. So we
    // don't need any extra code here
    Ok(())
}

use trustify_entity::crypto_remediation;

const CRYPTO_REMEDIATION_MIGRATION: &str = "m0002740_preload_nist_crypto_remediation";

/// All remediation rows, including metadata, in a deterministic order.
async fn crypto_remediation_rows(
    ctx: &TrustifyContext,
) -> anyhow::Result<Vec<crypto_remediation::Model>> {
    use sea_orm::{EntityTrait, QueryOrder};

    Ok(crypto_remediation::Entity::find()
        .order_by_asc(crypto_remediation::Column::AlgorithmName)
        .order_by_asc(crypto_remediation::Column::AlgorithmPrimitive)
        .all(&ctx.db)
        .await?)
}

/// Compare all five source fields, including nulls, and check generated UUIDv7 IDs.
async fn assert_crypto_remediation_source(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use serde_json::{Value, json};

    let mut expected: Vec<Value> = serde_json::from_str(include_str!(
        "../src/m0002740_preload_nist_crypto_remediation/NIST-Only-PQC-Remediation-2026-11.display.json"
    ))?;
    let mut actual = crypto_remediation_rows(ctx)
        .await?
        .into_iter()
        .map(|row| {
            assert_eq!(row.id.get_version_num(), 7);
            json!({
                "algorithm_name": row.algorithm_name,
                "algorithm_primitive": row.algorithm_primitive,
                "replacement_name": row.replacement_name,
                "replacement_standard": row.replacement_standard,
                "replacement_primitive": row.replacement_primitive,
            })
        })
        .collect::<Vec<_>>();
    expected.sort_by_cached_key(Value::to_string);
    actual.sort_by_cached_key(Value::to_string);
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 32);
    Ok(())
}

/// Insert arbitrary operator-managed mappings directly, without an application upload API.
async fn insert_crypto_remediations(
    ctx: &TrustifyContext,
    keys: &[(&str, Option<&str>)],
) -> anyhow::Result<Vec<crypto_remediation::Model>> {
    use sea_orm::{ActiveModelTrait, Set, prelude::TimeDateTimeWithTimeZone};
    use uuid::Uuid;

    let mut rows = Vec::new();
    for (name, primitive) in keys {
        rows.push(
            crypto_remediation::ActiveModel {
                id: Set(Uuid::now_v7()),
                algorithm_name: Set((*name).into()),
                algorithm_primitive: Set(primitive.map(str::to_owned)),
                replacement_name: Set("operator recommendation".into()),
                replacement_standard: Set(Some("operator standard".into())),
                replacement_primitive: Set(None),
                updated_at: Set(TimeDateTimeWithTimeZone::UNIX_EPOCH),
            }
            .insert(&ctx.db)
            .await?,
        );
    }
    Ok(rows)
}

/// Fresh database migration seeds exactly the bundled 32 mappings with UUIDv7 IDs.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_fresh(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given a fresh database, already migrated by the test context.
    // When its persisted reference rows are read, no runtime population is needed.
    // Then all five fields, including nulls and advisory text, match the sole source.
    assert_crypto_remediation_source(ctx).await
}

/// Empty-table seeding is reversible, and migration history prevents reseeding.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_up_down_up(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given an empty reference table immediately before the seed migration.
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());

    // When the seed runs, normal migration history prevents a second application.
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_crypto_remediation_source(ctx).await?;
    let seeded = crypto_remediation_rows(ctx).await?;
    migrator.up(&ctx.db, None).await?;
    assert_eq!(crypto_remediation_rows(ctx).await?, seeded);

    // Then rollback removes the unchanged seed and allows it to be applied again.
    migrator.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_crypto_remediation_source(ctx).await
}

/// The initial seed replaces earlier development mappings, including overlapping natural keys.
#[test_context(TrustifyContext)]
#[rstest::rstest]
#[case::foreign(vec![("foreign-only", None)])]
#[case::shared(vec![("rsa", None), ("RSA-2048", Some("KEM"))])]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_replaces_development_data(
    ctx: &TrustifyContext,
    #[case] keys: Vec<(&str, Option<&str>)>,
) -> anyhow::Result<()> {
    // Given development mappings, whether foreign or sharing bundled natural keys.
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    insert_crypto_remediations(ctx, &keys).await?;

    // When normal migration Up initializes the reference data.
    migrator.up(&ctx.db, Some(steps)).await?;

    // Then only the exact bundled mappings remain, with no stale development rows.
    assert_crypto_remediation_source(ctx).await
}

/// A failed seed restores development mappings, and migration history permits a retry.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_failure_is_atomic(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::ConnectionTrait;

    // Given development data and a constraint that rejects the bundled mappings.
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    insert_crypto_remediations(ctx, &[("foreign-only", None)]).await?;
    let original = crypto_remediation_rows(ctx).await?;
    ctx.db
        .execute_unprepared(
            "ALTER TABLE crypto_remediation \
             ADD CONSTRAINT crypto_remediation_seed_rejected \
             CHECK (algorithm_name = 'foreign-only')",
        )
        .await?;

    // When insertion fails after the table has been cleared.
    let error = migrator.up(&ctx.db, Some(steps)).await.unwrap_err();

    // Then the transaction restores every original row, including IDs and timestamps.
    assert!(
        error
            .to_string()
            .contains("crypto_remediation_seed_rejected")
    );
    assert_eq!(crypto_remediation_rows(ctx).await?, original);

    // When the constraint is removed, the same migration can be retried successfully.
    ctx.db
        .execute_unprepared(
            "ALTER TABLE crypto_remediation DROP CONSTRAINT crypto_remediation_seed_rejected",
        )
        .await?;
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_crypto_remediation_source(ctx).await
}

/// Rollback compares all five source fields, preserving customized and foreign rows verbatim.
#[test_context(TrustifyContext)]
#[rstest::rstest]
#[case::algorithm_name(crypto_remediation::Column::AlgorithmName)]
#[case::algorithm_primitive(crypto_remediation::Column::AlgorithmPrimitive)]
#[case::replacement_name(crypto_remediation::Column::ReplacementName)]
#[case::replacement_standard(crypto_remediation::Column::ReplacementStandard)]
#[case::replacement_primitive(crypto_remediation::Column::ReplacementPrimitive)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_rollback_preserves_customizations(
    ctx: &TrustifyContext,
    #[case] column: crypto_remediation::Column,
) -> anyhow::Result<()> {
    use sea_orm::ActiveModelTrait;

    // Given a seeded row with null source fields, customized in exactly one of the five fields.
    let mut customized: crypto_remediation::ActiveModel = crypto_remediation_rows(ctx)
        .await?
        .into_iter()
        .find(|row| row.algorithm_name == "rsa")
        .unwrap()
        .into();
    customized.set(column, "operator customization".into());
    let customized = customized.update(&ctx.db).await?;
    let foreign = insert_crypto_remediations(ctx, &[("foreign-only", None)]).await?;
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;

    // When the seed migration is rolled back.
    migrator.down(&ctx.db, Some(steps)).await?;

    // Then only unchanged bundled rows are deleted, including those with matching nulls.
    let remaining = crypto_remediation_rows(ctx).await?;
    assert_eq!(remaining.len(), 2);
    assert!(remaining.contains(&customized));
    assert!(remaining.contains(&foreign[0]));
    Ok(())
}

/// The normal seed is not a separately runnable data migration and ignores data skip controls.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_is_normal(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use migration::data::MigratorWithData;

    // Given an empty reference table and data migrations disabled.
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    let skipping = Migrator::new(
        ctx.storage.clone(),
        Options {
            skip_all: true,
            ..Default::default()
        },
    );

    // When normal database migrations run.
    skipping.up(&ctx.db, Some(steps)).await?;

    // Then the seed still installs the bundled mappings and is absent from the data runner.
    assert_crypto_remediation_source(ctx).await?;
    assert!(
        !Migrator::data_migrations()
            .iter()
            .any(|migration| migration.name() == CRYPTO_REMEDIATION_MIGRATION)
    );
    Ok(())
}
