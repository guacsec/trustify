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

/// The concurrent CPE index is valid, covers the ID, rolls back, and tolerates a manual index.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cpe_vendor_product_version_index_migration(ctx: &TrustifyContext) -> anyhow::Result<()> {
    use sea_orm::ConnectionTrait;
    use trustify_common::db::sql;

    let index_definition = async || -> anyhow::Result<Option<String>> {
        Ok(ctx
            .db
            .query_one_raw(sql(
                "SELECT pg_get_indexdef(indexrelid) AS indexdef FROM pg_index \
                 WHERE indexrelid = to_regclass('public.cpe_vendor_product_version_idx') \
                 AND indisvalid AND indisready",
                [],
            ))
            .await?
            .map(|row| row.try_get::<String>("", "indexdef"))
            .transpose()?)
    };
    let definition = "CREATE INDEX cpe_vendor_product_version_idx ON public.cpe \
                      USING btree (vendor, product, version) INCLUDE (id)";
    assert_eq!(index_definition().await?.as_deref(), Some(definition));

    let migrator = without_backfill(ctx);
    let steps = since(
        &migrator,
        &ctx.db,
        "m0002730_cpe_vendor_product_version_index",
    )
    .await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert_eq!(index_definition().await?, None);

    // An operator may already have installed the index to mitigate a slow query.
    ctx.db.execute_unprepared(definition).await?;
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_eq!(index_definition().await?.as_deref(), Some(definition));
    Ok(())
}

/// Queue installation leaves existing advisories to the extraction of the SBOMs, which sees all of
/// them, and reinstalls verdict work metadata.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn extraction_queue_migration_queues_no_existing_advisories(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::ConnectionTrait;
    use trustify_common::db::sql;
    use uuid::Uuid;

    let sbom = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    ctx.db
        .execute_unprepared("DELETE FROM correlation_extraction_queue")
        .await?;
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, "m0002590_correlation_extraction_queue").await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    migrator.up(&ctx.db, Some(steps)).await?;
    // Later, m0002620 leaves SBOMs to refresh jobs.
    let rows = ctx
        .db
        .query_all_raw(sql(
            "SELECT entity_id FROM correlation_extraction_queue",
            [],
        ))
        .await?;
    assert_eq!(rows.len(), 0);
    let state = ctx.db.query_one_raw(sql("SELECT generation IS NULL AND completed_at IS NULL AND completed_revision=0 AND completed_input_revision=0 AS uncomputed FROM correlation_verdict_state WHERE sbom_id=$1", vec![sbom.into()])).await?.unwrap();
    assert!(state.try_get::<bool>("", "uncomputed")?);
    Ok(())
}

/// SBOMs leave the ingestion queue for refresh jobs, and downgrading requeues unchecked ones.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn unified_refresh_migration_moves_sboms_to_refresh_jobs(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ConnectionTrait, DbErr};
    use trustify_common::db::sql;
    use uuid::Uuid;

    let queued = async || -> anyhow::Result<Vec<(String, Uuid)>> {
        Ok(ctx
            .db
            .query_all_raw(sql(
                "SELECT entity_type, entity_id FROM correlation_extraction_queue ORDER BY entity_type",
                vec![],
            ))
            .await?
            .iter()
            .map(|row| Ok((row.try_get("", "entity_type")?, row.try_get("", "entity_id")?)))
            .collect::<Result<_, DbErr>>()?)
    };
    let sbom = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    let advisory = Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
    assert_eq!(queued().await?, vec![("advisory".to_string(), advisory)]);
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, "m0002620_correlation_unified_refresh").await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert_eq!(
        queued().await?,
        vec![
            ("advisory".to_string(), advisory),
            ("sbom".to_string(), sbom)
        ]
    );
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_eq!(queued().await?, vec![("advisory".to_string(), advisory)]);
    Ok(())
}

/// Freshness metadata can be recreated without removing documents or their evidence.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn freshness_migration_preserves_documents_and_resets_to_unknown(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ConnectionTrait, EntityTrait};
    use trustify_common::db::sql;
    use trustify_entity::{advisory, sbom};
    use uuid::Uuid;

    let id = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    // Seed evidence directly: this test exercises schema lifecycle, not extraction.
    ctx.db.execute_unprepared("INSERT INTO correlation_evidence(id,sbom_id,node_id,advisory_id,vulnerability_id,status,confidence,extractor,created_at,confidence_factors,source_assertions) SELECT gen_random_uuid(),n.sbom_id,n.node_id,a.advisory_id,a.vulnerability_id,'affected',1,'purl',now(),'[]'::jsonb,jsonb_build_array(jsonb_build_object('kind','purl','id',a.id)) FROM sbom_node n CROSS JOIN purl_status a LIMIT 1").await?;
    assert_eq!(evidence_count(&ctx.db).await?, 1);
    let documents = sbom::Entity::find().all(&ctx.db).await?;
    let advisories = advisory::Entity::find().all(&ctx.db).await?;
    ctx.db
        .execute_unprepared(
            "UPDATE correlation_extraction_state SET completed_revision=1,completed_at=now()",
        )
        .await?;
    let migrator = without_backfill(ctx);
    let steps = since(&migrator, &ctx.db, "m0002570_correlation_freshness").await?;
    migrator.down(&ctx.db, Some(steps)).await?;
    assert_eq!(evidence_count(&ctx.db).await?, 1);
    assert_eq!(sbom::Entity::find().all(&ctx.db).await?, documents);
    assert_eq!(advisory::Entity::find().all(&ctx.db).await?, advisories);
    migrator.up(&ctx.db, Some(steps)).await?;
    assert_eq!(evidence_count(&ctx.db).await?, 1);
    assert_eq!(sbom::Entity::find().all(&ctx.db).await?, documents);
    assert_eq!(advisory::Entity::find().all(&ctx.db).await?, advisories);
    let state = ctx.db.query_one_raw(sql("SELECT completed_revision=0 AND completed_at IS NULL AS unknown FROM correlation_extraction_state WHERE sbom_id=$1", vec![id.into()])).await?.unwrap();
    assert!(state.try_get::<bool>("", "unknown")?);
    let count = ctx.db.query_one_raw(sql("SELECT sum(documents)::bigint AS unknown FROM correlation_extraction_count WHERE revision=0", [])).await?.unwrap();
    assert_eq!(count.try_get::<i64>("", "unknown")?, 1);
    Ok(())
}

/// The number of evidence rows, read without the entity, whose columns may not exist yet.
async fn evidence_count(db: &sea_orm::DatabaseConnection) -> anyhow::Result<i64> {
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    Ok(db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS count FROM correlation_evidence".to_string(),
        ))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no count"))?
        .try_get("", "count")?)
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

/// Any preexisting mapping blocks seeding without losing operator data.
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
