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
    migrator.down(&ctx.db, Some(1)).await?;
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
    migrator.up(&ctx.db, Some(1)).await?;
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
