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
    use sea_orm::{ActiveModelTrait, ConnectionTrait, DbBackend, EntityTrait, Set, Statement};
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
    for identifier in [
        "pkg:rpm/redhat/mediawiki",
        "pkg:rpm/redhat/mediawiki?arch=src",
    ] {
        correlation_evidence::ActiveModel {
            id: Set(Uuid::new_v4()),
            sbom_id: Set(Uuid::parse_str(&sbom.id)?),
            node_id: Set("SPDXRef-Package".into()),
            advisory_id: Set(rows[0].advisory_id),
            vulnerability_id: Set(rows[0].vulnerability_id.clone()),
            status: Set(correlation_evidence::AssertionStatus::Affected),
            confidence: Set(1.0),
            extractor: Set("purl".into()),
            matched_value: Set(Some(serde_json::json!({"identifier": identifier}))),
            created_at: Set(sea_orm::prelude::TimeDateTimeWithTimeZone::UNIX_EPOCH),
        }
        .insert(&ctx.db)
        .await?;
    }
    assert_eq!(
        correlation_evidence::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        2
    );
    // Also roll back the newer evidence-origin metadata migration.
    migrator.down(&ctx.db, Some(3)).await?;
    assert_eq!(
        correlation_evidence::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        1
    );
    ctx.db
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT id FROM purl_status_effective".to_string(),
        ))
        .await?;
    migrator.up(&ctx.db, Some(3)).await?;
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
    Ok(())
}

/// Old rows get provenance without changing their identity, ranges, or policy metadata. Future
/// extractors and rows already carrying provenance must not be reclassified by this migration.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn correlation_assertion_origin_upgrade_and_downgrade(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use trustify_entity::correlation_evidence::{self, AssertionStatus};
    use uuid::Uuid;

    let sbom = ctx.ingest_document("spdx/simple.json").await?;
    let advisory = ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    let migrator = Migrator::new(ctx.storage.clone(), ());
    migrator.down(&ctx.db, Some(2)).await?;
    let mut expected = Vec::new();
    for (extractor, origin, null_value) in [
        ("purl", Some("stated"), false),
        ("purl_stream", Some("stated"), false),
        ("purl_vls_range", Some("stated"), false),
        ("purl_custom_range", Some("stated"), false),
        ("cpe", Some("stated"), false),
        ("digest", Some("stated"), false),
        ("product_identifier", Some("stated"), false),
        ("purl_default", Some("default"), false),
        ("cpe_default", Some("default"), false),
        ("purl_fixed_as_first_fixed", Some("publisher_policy"), false),
        (
            "purl_fixed_as_first_fixed_before",
            Some("publisher_policy"),
            false,
        ),
        ("purl_any_version", Some("publisher_policy"), false),
        ("purl_first_fixed", Some("stated"), false),
        ("purl_first_fixed_before", Some("inferred"), false),
        ("purl_first_affected", Some("stated"), false),
        ("purl_last_affected", Some("stated"), false),
        ("purl_suse_recommended", Some("inferred"), false),
        ("purl_suse_recommended_before", Some("inferred"), false),
        ("future_extractor", None, false),
        // Already classified evidence must keep its origin, even for a historical ID.
        ("purl", Some("publisher_policy"), false),
        // An old row without matched-value JSON is still classifiable.
        ("digest", Some("stated"), true),
    ] {
        let id = Uuid::new_v4();
        let mut value = serde_json::json!({
            "identifier": format!("demo-{id}"),
            "ranges": [{"scheme": "rpm", "low": null, "high": null}],
            "enabled_by": {"key": "fixed_is_first_fixed"}
        });
        if origin == Some("publisher_policy") && extractor == "purl" {
            value["origin"] = "publisher_policy".into();
        }
        let mut row = correlation_evidence::ActiveModel {
            id: Set(id),
            sbom_id: Set(Uuid::parse_str(&sbom.id)?),
            node_id: Set(if null_value {
                "SPDXRef-A"
            } else {
                "SPDXRef-Package"
            }
            .into()),
            advisory_id: Set(Uuid::parse_str(&advisory.id)?),
            vulnerability_id: Set("CVE-2023-33201".into()),
            status: Set(AssertionStatus::Affected),
            confidence: Set(0.8),
            extractor: Set(extractor.into()),
            matched_value: Set(Some(value.clone())),
            created_at: Set(sea_orm::prelude::TimeDateTimeWithTimeZone::UNIX_EPOCH),
        };
        if null_value {
            row.matched_value = Set(None);
            value = serde_json::json!({"identifier": ""});
        }
        let row = row.insert(&ctx.db).await?;
        if let Some(origin) = origin {
            value["origin"] = origin.into();
        }
        expected.push((row, value));
    }
    migrator.up(&ctx.db, Some(2)).await?;
    for (old, value) in &expected {
        let row = correlation_evidence::Entity::find_by_id(old.id)
            .one(&ctx.db)
            .await?
            .unwrap();
        assert_eq!(row.matched_value.as_ref(), Some(value));
        assert_eq!(
            row,
            correlation_evidence::Model {
                matched_value: Some(value.clone()),
                ..old.clone()
            }
        );
    }
    migrator.down(&ctx.db, Some(2)).await?;
    for (old, value) in &expected {
        let row = correlation_evidence::Entity::find_by_id(old.id)
            .one(&ctx.db)
            .await?
            .unwrap();
        let mut value = value.clone();
        value.as_object_mut().unwrap().remove("origin");
        assert_eq!(row.matched_value, Some(value));
    }
    migrator.up(&ctx.db, Some(2)).await?;
    Ok(())
}
