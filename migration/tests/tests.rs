#![recursion_limit = "256"]
use migration::{Migrator, MigratorTraitSelf};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

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

/// The new relationship is nullable for old data and exposed by the fundamental bridge view.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn qualified_purl_relationship_upgrade_and_downgrade(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use trustify_entity::{correlation_evidence, purl_status, qualified_purl};
    use uuid::Uuid;

    let migrator = without_backfill(ctx);
    ctx.ingest_document("csaf/CVE-2024-34502.json").await?;
    let rows = purl_status::Entity::find().all(&ctx.db).await?;
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| row.qualified_purl_id.is_some()));
    assert!(!purl_status::find_effective().all(&ctx.db).await?.is_empty());
    let original_ids = rows
        .iter()
        .map(|r| r.id)
        .collect::<std::collections::BTreeSet<_>>();

    // Reject dangling references while leaving the original PURL data intact.
    let referenced = rows[0].qualified_purl_id.unwrap();
    assert!(
        qualified_purl::Entity::delete_by_id(referenced)
            .exec(&ctx.db)
            .await
            .is_err()
    );
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    for (identifier, provider, status) in [
        (
            "pkg:rpm/redhat/mediawiki",
            "A",
            correlation_evidence::AssertionStatus::Affected,
        ),
        (
            "pkg:rpm/redhat/mediawiki?arch=src",
            "A",
            correlation_evidence::AssertionStatus::Affected,
        ),
        (
            "pkg:rpm/redhat/mediawiki",
            "B",
            correlation_evidence::AssertionStatus::Affected,
        ),
        (
            "pkg:rpm/redhat/mediawiki",
            "A",
            correlation_evidence::AssertionStatus::NotAffected,
        ),
    ] {
        correlation_evidence::ActiveModel {
            id: Set(Uuid::new_v4()),
            sbom_id: Set(Uuid::parse_str(&sbom.id)?),
            node_id: Set("SPDXRef-Package".into()),
            advisory_id: Set(rows[0].advisory_id),
            vulnerability_id: Set(rows[0].vulnerability_id.clone()),
            status: Set(status),
            confidence: Set(1.0),
            extractor: Set("purl".into()),
            matched_value: Set(Some(serde_json::json!({
                "identifier": identifier,
                "source_provider": {"identifiers": [format!("name:{provider}")]}
            }))),
            created_at: Set(sea_orm::prelude::TimeDateTimeWithTimeZone::UNIX_EPOCH),
            confidence_factors: sea_orm::NotSet,
            source_assertions: Set(serde_json::json!([{"kind": "purl", "id": rows[0].id}])),
        }
        .insert(&ctx.db)
        .await?;
    }
    assert_eq!(
        correlation_evidence::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        4
    );
    let evidence = correlation_evidence::Entity::find().all(&ctx.db).await?;
    // Roll back source columns and the bridge view, preserving distinct evidence rows.
    let migrations = since(&migrator, &ctx.db, "m0002530_purl_status_effective").await?;
    migrator.down(&ctx.db, Some(migrations)).await?;
    assert_eq!(evidence_count(&ctx.db).await?, 4);
    migrator.up(&ctx.db, Some(migrations)).await?;
    let restored = purl_status::Entity::find().all(&ctx.db).await?;
    assert_eq!(
        restored
            .iter()
            .map(|r| r.id)
            .collect::<std::collections::BTreeSet<_>>(),
        original_ids
    );
    assert!(restored.iter().all(|row| row.qualified_purl_id.is_none()));
    assert!(!purl_status::find_effective().all(&ctx.db).await?.is_empty());
    for row in evidence {
        assert_eq!(
            correlation_evidence::Entity::find_by_id(row.id)
                .one(&ctx.db)
                .await?,
            Some(row)
        );
    }
    Ok(())
}

/// Roll back the complete PR schema with populated assertions, then upgrade a database that
/// already contains advisories and SBOMs. Both unspecified schemes can scope product identifiers.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn correlation_migrations_upgrade_and_downgrade(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait, QuerySelect};
    use trustify_entity::{advisory, advisory_vulnerability_product_identifier, sbom};

    ctx.ingest_document("spdx/simple.json").await?;
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    ctx.ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
        .await?;
    assert!(
        advisory_vulnerability_product_identifier::Entity::find()
            .count(&ctx.db)
            .await?
            > 0
    );
    ctx.db
        .execute_unprepared(
            r#"
INSERT INTO version_range (id, version_scheme_id) VALUES
    ('00000000-0000-0000-0000-000000000001', 'vls'),
    ('00000000-0000-0000-0000-000000000002', 'custom');
INSERT INTO advisory_vulnerability_product_identifier
    (id, advisory_id, vulnerability_id, status, identifier_type, value, version_range_id)
SELECT gen_random_uuid(), a.advisory_id, a.vulnerability_id, a.status, a.identifier_type,
    a.value, vr.id
FROM (SELECT * FROM advisory_vulnerability_product_identifier LIMIT 1) a
CROSS JOIN version_range vr
WHERE vr.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002');
"#,
        )
        .await?;
    let advisories = advisory::Entity::find().count(&ctx.db).await?;
    let sboms = sbom::Entity::find().count(&ctx.db).await?;
    let migrator = without_backfill(ctx);
    let migrations = since(&migrator, &ctx.db, "m0002410_create_correlation_evidence").await?;
    migrator.down(&ctx.db, Some(migrations)).await?;
    assert_eq!(
        advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .count(&ctx.db)
            .await?,
        advisories
    );
    assert_eq!(sbom::Entity::find().count(&ctx.db).await?, sboms);
    migrator.up(&ctx.db, Some(migrations)).await?;
    assert_eq!(advisory::Entity::find().count(&ctx.db).await?, advisories);
    assert_eq!(sbom::Entity::find().count(&ctx.db).await?, sboms);
    assert_eq!(evidence_count(&ctx.db).await?, 0);
    Ok(())
}

/// Upgrading preserves old associations and evidence; source applicability is populated only
/// by fresh ingestion/extraction. Downgrading removes only the added links.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn remediation_assertions_upgrade_and_downgrade(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use trustify_entity::{
        advisory_vulnerability_product_identifier, correlation_evidence,
        correlation_evidence::{AssertionStatus, SourceAssertionRef},
        remediation_cpe_assertion, remediation_product_status, remediation_purl_status,
    };
    use uuid::Uuid;

    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;
    let advisory = ctx
        .ingest_document("scenarios/S20_cpe_range_wago/vex/vde-2025-081.json")
        .await?;
    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let links = remediation_cpe_assertion::Entity::find()
        .all(&ctx.db)
        .await?;
    assert!(!links.is_empty());
    let evidence = correlation_evidence::ActiveModel {
        id: Set(Uuid::new_v4()),
        sbom_id: Set(Uuid::parse_str(&sbom.id)?),
        node_id: Set("SPDXRef-Package".into()),
        advisory_id: Set(Uuid::parse_str(&advisory.id)?),
        vulnerability_id: Set("CVE-2099-2738".into()),
        status: Set(AssertionStatus::Affected),
        confidence: Set(0.8),
        extractor: Set("cpe".into()),
        matched_value: Set(None),
        created_at: Set(sea_orm::prelude::TimeDateTimeWithTimeZone::UNIX_EPOCH),
        confidence_factors: Set(serde_json::json!([])),
        source_assertions: Set(serde_json::to_value([SourceAssertionRef::Cpe(
            links[0].assertion_id,
        )])?),
    }
    .insert(&ctx.db)
    .await?;

    // The same identifier/status/context retains distinct version ranges across rollback.
    ctx.ingest_document("scenarios/S19_sku_correlation/vex/hbsa-2025-0003.json")
        .await?;
    let identifiers = advisory_vulnerability_product_identifier::Entity::find()
        .all(&ctx.db)
        .await?;
    let source = identifiers
        .iter()
        .find(|row| row.version_range_id.is_some())
        .unwrap();
    let mut duplicate: advisory_vulnerability_product_identifier::ActiveModel =
        source.clone().into();
    duplicate.id = Set(Uuid::new_v4());
    duplicate.version_range_id = Set(None);
    duplicate.insert(&ctx.db).await?;

    let legacy_purls = remediation_purl_status::Entity::find().all(&ctx.db).await?;
    let legacy_products = remediation_product_status::Entity::find()
        .all(&ctx.db)
        .await?;
    assert!(!legacy_purls.is_empty());
    assert!(!legacy_products.is_empty());
    let migrator = without_backfill(ctx);
    let migrations = since(&migrator, &ctx.db, "m0002580_remediation_assertions").await?;
    migrator.down(&ctx.db, Some(migrations)).await?;
    assert_eq!(evidence_count(&ctx.db).await?, 1);
    assert_eq!(
        remediation_purl_status::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        legacy_purls.len()
    );
    assert_eq!(
        remediation_product_status::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        legacy_products.len()
    );
    assert_eq!(
        advisory_vulnerability_product_identifier::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        identifiers.len() + 1
    );
    migrator.up(&ctx.db, Some(migrations)).await?;
    assert!(
        remediation_cpe_assertion::Entity::find()
            .all(&ctx.db)
            .await?
            .is_empty()
    );
    assert_eq!(
        correlation_evidence::Entity::find_by_id(evidence.id)
            .one(&ctx.db)
            .await?
            .unwrap(),
        evidence
    );
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

/// Explicitly run the seed independently of schema migration history.
async fn run_crypto_remediation(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use migration::data::{Direction, Runner};

    Runner {
        database: ctx.db.clone().into(),
        storage: ctx.storage.clone().into(),
        direction: Direction::Up,
        migrations: vec![CRYPTO_REMEDIATION_MIGRATION.into()],
        options: Default::default(),
    }
    .run::<Migrator>()
    .await
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

/// Empty-table seeding is reversible; history prevents reruns, while explicit reruns refuse data.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_up_down_up(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::DbErr;

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

    // When an operator explicitly reruns Up against the populated table.
    let error = run_crypto_remediation(ctx).await.unwrap_err();

    // Then it refuses the operation without changing any IDs, timestamps, or source values.
    assert!(matches!(
        error.downcast_ref::<DbErr>(),
        Some(DbErr::Migration(message)) if message.contains("crypto_remediation must be empty")
    ));
    assert_eq!(crypto_remediation_rows(ctx).await?, seeded);

    // When rolled back and reapplied, unchanged seed rows disappear and can be seeded again.
    migrator.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_crypto_remediation_source(ctx).await
}

/// Any preexisting mapping blocks both migration entry points without losing operator data.
#[test_context(TrustifyContext)]
#[rstest::rstest]
#[case::foreign(vec![("foreign-only", None)])]
#[case::shared(vec![("rsa", None), ("RSA-2048", Some("KEM"))])]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_refuses_preexisting_data(
    ctx: &TrustifyContext,
    #[case] keys: Vec<(&str, Option<&str>)>,
) -> anyhow::Result<()> {
    use sea_orm::DbErr;

    // Given operator mappings, whether foreign or sharing bundled natural keys.
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    insert_crypto_remediations(ctx, &keys).await?;
    let original = crypto_remediation_rows(ctx).await?;

    // When normal migration Up encounters a nonempty table.
    let error = migrator.up(&ctx.db, Some(steps)).await.unwrap_err();

    // Then it reports a migration error and preserves every row, including metadata.
    assert!(matches!(
        error,
        DbErr::Migration(message) if message.contains("crypto_remediation must be empty")
    ));
    assert_eq!(crypto_remediation_rows(ctx).await?, original);

    // When explicitly invoked through the data runner, the same refusal is lossless.
    let error = run_crypto_remediation(ctx).await.unwrap_err();
    assert!(matches!(
        error.downcast_ref::<DbErr>(),
        Some(DbErr::Migration(message)) if message.contains("crypto_remediation must be empty")
    ));
    assert_eq!(crypto_remediation_rows(ctx).await?, original);
    Ok(())
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

/// Skipping leaves an empty table untouched and allows explicit deferred seeding and rollback.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn crypto_remediation_preload_can_be_deferred(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Given an empty reference table whose initial data seed will be skipped.
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, CRYPTO_REMEDIATION_MIGRATION).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    let skipping = Migrator::new(
        ctx.storage.clone(),
        Options {
            skip: vec![CRYPTO_REMEDIATION_MIGRATION.into()],
            ..Default::default()
        },
    );

    // When schema migration skips the seed, Up and Down both leave the table empty.
    skipping.up(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    skipping.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    skipping.up(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());

    // When the deferred seed is run explicitly through the data runner.
    run_crypto_remediation(ctx).await?;

    // Then exactly the bundled source is installed, and ordinary rollback removes it.
    assert_crypto_remediation_source(ctx).await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert!(crypto_remediation_rows(ctx).await?.is_empty());
    Ok(())
}
