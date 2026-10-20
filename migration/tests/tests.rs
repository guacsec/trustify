#![recursion_limit = "256"]
use migration::{Migrator, MigratorTraitSelf};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

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

    let migrator = Migrator::new(ctx.storage.clone(), ());
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
            source_assertions: sea_orm::NotSet,
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
    let migrations = since(&migrator, &ctx.db, "m0002560_purl_status_effective").await?;
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
    let migrator = Migrator::new(ctx.storage.clone(), ());
    let migrations = since(&migrator, &ctx.db, "m0002390_create_correlation_evidence").await?;
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
    let migrator = Migrator::new(ctx.storage.clone(), ());
    let migrations = since(&migrator, &ctx.db, "m0002690_remediation_assertions").await?;
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
