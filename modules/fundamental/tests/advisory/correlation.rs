use migration::{Migrator, MigratorTraitSelf, SchemaManager, data::Options};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait,
};
use test_context::test_context;
use trustify_common::{
    db::{ReadWrite, pagination_cache::PaginationCache, sql},
    model::Paginated,
};
use trustify_entity::{advisory, correlation_evidence};
use trustify_module_correlation::{
    extractor::Extractors,
    model::{FreshnessStatus, IdentifierKind, IdentifierRef, ResolutionRequest, VerdictStatus},
    service::{CorrelationService, extraction, freshness, projection, tuning::WorkerConfig},
};
use trustify_module_fundamental::advisory::service::AdvisoryService;
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

async fn advisory_document() -> anyhow::Result<serde_json::Value> {
    let mut document: serde_json::Value =
        serde_json::from_slice(&document_bytes("csaf/cve-2023-33201.json").await?)?;
    document["product_tree"] = serde_json::json!({
        "full_product_names": [{
            "name": "hyper 0.14.1",
            "product_id": "hyper",
            "product_identification_helper": { "purl": "pkg:cargo/hyper@0.14.1" }
        }]
    });
    document["vulnerabilities"] = serde_json::json!([{
        "cve": "CVE-2023-33201",
        "product_status": { "known_affected": ["hyper"] },
        "remediations": [{
            "category": "vendor_fix", "details": "Upgrade hyper",
            "product_ids": ["hyper"], "url": "https://example.com/hyper"
        }]
    }]);
    Ok(document)
}

fn mark_fixed(document: &mut serde_json::Value) {
    document["document"]["tracking"]["current_release_date"] = "2023-10-06T20:23:30Z".into();
    document["document"]["tracking"]["version"] = "2".into();
    document["vulnerabilities"][0]["product_status"] = serde_json::json!({ "fixed": ["hyper"] });
    document["vulnerabilities"][0]["remediations"] = serde_json::json!([]);
}

async fn extract(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let db = ReadWrite::new(ctx.db.clone());
    let extractors = Extractors::default();
    while extraction::run_step(&db, &extractors, &WorkerConfig::default()).await?
        | freshness::run_step(&db, &extractors, &WorkerConfig::default()).await?
    {}
    Ok(())
}

async fn publish(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let db = ReadWrite::new(ctx.db.clone());
    while projection::run_step(&db, &WorkerConfig::default()).await? {}
    Ok(())
}

async fn assert_current(
    ctx: &TrustifyContext,
    sbom: Uuid,
    current: Uuid,
    expected: VerdictStatus,
) -> anyhow::Result<()> {
    let service = CorrelationService::default();
    let cache = PaginationCache::for_test();
    let tx = ctx.db.begin().await?;
    let preview = service.correlate_sbom(sbom, true, &tx).await?;
    assert!(!preview.verdicts.is_empty());
    for verdict in &preview.verdicts {
        assert_eq!(verdict.status, expected);
        assert!(!verdict.evidence.is_empty());
        assert!(verdict.evidence.iter().all(|e| e.advisory_id == current));
        assert_eq!(
            verdict.evidence.iter().any(|e| !e.remediations.is_empty()),
            expected == VerdictStatus::Affected
        );
    }
    let identifier = IdentifierRef {
        kind: IdentifierKind::Purl,
        value: "pkg:cargo/hyper@0.14.1".into(),
    };
    for product_context in [vec![], vec![identifier.clone()]] {
        let query = service
            .query_identifier_with(
                identifier.clone(),
                &ResolutionRequest {
                    product_context,
                    ..Default::default()
                },
                &tx,
            )
            .await?;
        assert!(!query.verdicts.is_empty());
        for verdict in query.verdicts {
            assert_eq!(verdict.status, expected);
            assert!(!verdict.matches.is_empty());
            assert!(verdict.matches.iter().all(|m| m.advisory_id == current));
            assert_eq!(
                verdict.matches.iter().any(|m| !m.remediations.is_empty()),
                expected == VerdictStatus::Affected
            );
        }
    }
    let page = service
        .verdict_page(
            sbom,
            &ResolutionRequest::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &cache,
            &tx,
        )
        .await?;
    assert_eq!(page.freshness.status, FreshnessStatus::Current);
    assert_eq!(page.total, Some(preview.verdicts.len() as u64));
    assert_eq!(page.items.len(), preview.verdicts.len());
    for verdict in page.items {
        assert_eq!(verdict.status, expected);
        assert!(verdict.evidence.iter().all(|e| e.advisory_id == current));
    }
    Ok(())
}

/// Historical evidence is retained and becomes eligible again when its replacement is deleted.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn deprecated_advisory_correlation_lifecycle(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut document = advisory_document().await?;
    let v1 = Uuid::parse_str(&ctx.ingest_json(&document).await?.id)?;
    let mut sbom_document: serde_json::Value =
        serde_json::from_slice(&document_bytes("correlation/osv/hyper-0.14.1.cdx.json").await?)?;
    let mut duplicate = sbom_document["components"][0].clone();
    duplicate["bom-ref"] = "hyper-copy".into();
    sbom_document["components"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    let sbom = Uuid::parse_str(&ctx.ingest_json(sbom_document).await?.id)?;
    extract(ctx).await?;
    publish(ctx).await?;
    assert_current(ctx, sbom, v1, VerdictStatus::Affected).await?;
    let v1_evidence = correlation_evidence::Entity::find()
        .filter(correlation_evidence::Column::AdvisoryId.eq(v1))
        .count(&ctx.db)
        .await?;
    assert!(v1_evidence > 0);

    mark_fixed(&mut document);
    let v2 = Uuid::parse_str(&ctx.ingest_json(&document).await?.id)?;
    assert!(
        advisory::Entity::find_by_id(v1)
            .one(&ctx.db)
            .await?
            .unwrap()
            .deprecated
    );
    let tx = ctx.db.begin().await?;
    assert_eq!(
        projection::state(&[sbom], &tx).await?[&sbom].status,
        FreshnessStatus::Stale
    );
    tx.commit().await?;
    extract(ctx).await?;
    publish(ctx).await?;
    assert_current(ctx, sbom, v2, VerdictStatus::Fixed).await?;

    // SBOM-direction extraction may store historical facts, but cannot make them eligible.
    let tx = ctx.db.begin().await?;
    Extractors::default().extract_for_sbom(sbom, &tx).await?;
    tx.commit().await?;
    publish(ctx).await?;
    assert_current(ctx, sbom, v2, VerdictStatus::Fixed).await?;
    assert_eq!(
        correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::AdvisoryId.eq(v1))
            .count(&ctx.db)
            .await?,
        v1_evidence,
    );

    let tx = ctx.db.begin().await?;
    assert!(
        AdvisoryService::new(PaginationCache::for_test())
            .delete_advisory(v2, &tx)
            .await?
    );
    tx.commit().await?;
    assert!(
        !advisory::Entity::find_by_id(v1)
            .one(&ctx.db)
            .await?
            .unwrap()
            .deprecated
    );
    let tx = ctx.db.begin().await?;
    assert_eq!(
        projection::state(&[sbom], &tx).await?[&sbom].status,
        FreshnessStatus::Stale
    );
    tx.commit().await?;
    // No extraction: restoring eligibility must reuse the older version's stored evidence.
    publish(ctx).await?;
    assert_current(ctx, sbom, v1, VerdictStatus::Affected).await?;

    // The semantics migration invalidates snapshots and gates incompatible workers.
    let migrations = Migrator::new(ctx.storage.clone(), Options::default()).migrations();
    let migration = migrations
        .iter()
        .find(|m| m.name() == "m0002720_correlation_current_advisories")
        .unwrap();
    let tx = ctx.db.begin().await?;
    let manager = SchemaManager::new(&tx);
    migration.down(&manager).await?;
    tx.commit().await?;
    let db = ReadWrite::new(ctx.db.clone());
    assert!(!projection::run_step(&db, &WorkerConfig::default()).await?);
    let tx = ctx.db.begin().await?;
    assert_eq!(
        projection::state(&[sbom], &tx).await?[&sbom].status,
        FreshnessStatus::Stale
    );
    migration.up(&SchemaManager::new(&tx)).await?;
    let revision = tx
        .query_one_raw(sql(
            "SELECT resolver_version FROM correlation_verdict_revision",
            vec![],
        ))
        .await?
        .unwrap();
    assert_eq!(revision.try_get::<i32>("", "resolver_version")?, 2);
    tx.commit().await?;
    publish(ctx).await?;
    assert_current(ctx, sbom, v1, VerdictStatus::Affected).await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn restored_advisory_pending_extraction(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut document = advisory_document().await?;
    let v1 = Uuid::parse_str(&ctx.ingest_json(&document).await?.id)?;
    mark_fixed(&mut document);
    let v2 = Uuid::parse_str(&ctx.ingest_json(&document).await?.id)?;
    let sbom = Uuid::parse_str(
        &ctx.ingest_document("correlation/osv/hyper-0.14.1.cdx.json")
            .await?
            .id,
    )?;
    let tx = ctx.db.begin().await?;
    AdvisoryService::new(PaginationCache::for_test())
        .delete_advisory(v2, &tx)
        .await?;
    tx.commit().await?;
    extract(ctx).await?;
    publish(ctx).await?;
    assert_current(ctx, sbom, v1, VerdictStatus::Affected).await?;
    Ok(())
}
