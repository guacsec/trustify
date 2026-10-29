use super::*;
use crate::{extractor::Extractors, model::FreshnessStatus, service::extraction};
use test_context::test_context;
use trustify_common::model::Paginated;
use trustify_test_context::TrustifyContext;

async fn drain_extraction(ctx: &TrustifyContext) -> anyhow::Result<()> {
    while extraction::run_step(&db::ReadWrite::new(ctx.db.clone()), &Extractors::default()).await? {
    }
    Ok(())
}

async fn fixture(ctx: &TrustifyContext) -> anyhow::Result<Uuid> {
    ctx.ingest_document("osv/RUSTSEC-2021-0079.json").await?;
    let id = Uuid::parse_str(
        &ctx.ingest_document("correlation/osv/hyper-0.14.1.cdx.json")
            .await?
            .id,
    )?;
    drain_extraction(ctx).await?;
    Ok(id)
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn zero_findings_are_distinct_from_uncomputed(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let id = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    let tx = ctx.db.begin().await?;
    assert!(state(&[id], &tx).await?[&id].generation.is_none());
    assert!(lag(&tx).await?.pending > 0);
    tx.commit().await?;
    drain_extraction(ctx).await?;
    while run_step(&db::ReadWrite::new(ctx.db.clone())).await? {}
    let tx = ctx.db.begin().await?;
    assert!(state(&[id], &tx).await?[&id].generation.is_some());
    assert_eq!(counts(&[id], &tx).await?[0].affected, 0);
    assert_eq!(
        state(&[id], &tx).await?[&id].status,
        FreshnessStatus::Current
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn snapshot_matches_resolver_and_is_readable_after_failed_refresh(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = fixture(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    while run_step(&db).await? {}
    let tx = ctx.db.begin().await?;
    let service = CorrelationService::default();
    let cache = PaginationCache::new(std::time::Duration::from_secs(60), 25);
    let request = ResolutionRequest {
        include_explanation: true,
        ..Default::default()
    };
    let page = service
        .verdict_page(
            id,
            &request,
            Paginated {
                total: true,
                ..Default::default()
            },
            &cache,
            &tx,
        )
        .await?;
    let live = service
        .correlate_sbom_with(id, false, &request, &tx)
        .await?;
    assert_eq!(page.items, live.verdicts);
    assert!(!page.items.is_empty());
    assert_eq!(page.total, Some(page.items.len() as u64));
    let original = page.freshness.generation;
    assert_eq!(page.freshness.status, FreshnessStatus::Current);
    let count = counts(&[id, id], &tx).await?;
    assert_eq!(count[0], count[1]);
    assert_eq!(count[0].remediations, 1);
    tx.execute_raw(sql(
        "UPDATE correlation_evidence SET matched_value='\"invalid\"'::jsonb WHERE sbom_id=$1",
        vec![id.into()],
    ))
    .await?;
    tx.commit().await?;
    assert!(run_step(&db).await?);
    let tx = ctx.db.begin().await?;
    let failed = service
        .verdict_page(id, &request, Paginated::default(), &cache, &tx)
        .await?;
    assert_eq!(failed.items, page.items);
    assert_eq!(failed.freshness.generation, original);
    assert_eq!(failed.freshness.status, FreshnessStatus::Stale);
    assert_eq!(lag(&tx).await?.failed, 1);
    // Ordinary reads and count-only reads use the prior snapshot, not invalid resolver input.
    for total in [false, true] {
        let empty = service
            .verdict_page(
                id,
                &request,
                Paginated {
                    limit: 0,
                    offset: 99,
                    total,
                },
                &cache,
                &tx,
            )
            .await?;
        assert!(empty.items.is_empty());
        assert_eq!(empty.total, total.then_some(page.items.len() as u64));
    }
    tx.commit().await?;
    let tx = ctx.db.begin().await?;
    freshness::refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    while run_step(&db).await? {}
    let tx = ctx.db.begin().await?;
    assert_eq!(
        state(&[id], &tx).await?[&id].status,
        FreshnessStatus::Current
    );
    assert_ne!(state(&[id], &tx).await?[&id].generation, original);
    assert_eq!(lag(&tx).await?.pending, 0);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn upstream_work_and_global_revisions_invalidate_without_eager_queue_expansion(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = fixture(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    while run_step(&db).await? {}
    let tx = ctx.db.begin().await?;
    let before = state(&[id], &tx).await?[&id].clone();
    tx.execute_raw(sql("INSERT INTO correlation_extraction_queue(id,entity_type,entity_id) VALUES($1,'advisory',$2)", vec![Uuid::now_v7().into(),Uuid::now_v7().into()])).await?;
    assert_eq!(state(&[id], &tx).await?[&id].status, FreshnessStatus::Stale);
    tx.commit().await?;
    drain_extraction(ctx).await?;
    let tx = ctx.db.begin().await?;
    assert_eq!(state(&[id], &tx).await?[&id], before);
    tx.execute_unprepared(
        "UPDATE correlation_verdict_revision SET revision=revision+1,changed_at=clock_timestamp()",
    )
    .await?;
    assert_eq!(lag(&tx).await?.pending, 1);
    assert_eq!(state(&[id], &tx).await?[&id].status, FreshnessStatus::Stale);
    tx.commit().await?;
    while run_step(&db).await? {}
    let tx = ctx.db.begin().await?;
    assert_eq!(
        state(&[id], &tx).await?[&id].status,
        FreshnessStatus::Current
    );
    assert_ne!(state(&[id], &tx).await?[&id].generation, before.generation);
    // A worker compiled with an older resolver never acknowledges a newer version.
    tx.execute_unprepared(
        "UPDATE correlation_verdict_revision SET resolver_version=2,revision=revision+1",
    )
    .await?;
    tx.commit().await?;
    assert!(!run_step(&db).await?);
    let tx = ctx.db.begin().await?;
    assert_eq!(lag(&tx).await?.pending, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn publication_rolls_back_and_cached_totals_follow_the_generation(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = fixture(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    while run_step(&db).await? {}
    let service = CorrelationService::default();
    let cache = PaginationCache::new(std::time::Duration::from_secs(60), 25);
    let page = Paginated {
        total: true,
        ..Default::default()
    };
    let tx = ctx.db.begin().await?;
    let first = service
        .verdict_page(id, &ResolutionRequest::default(), page, &cache, &tx)
        .await?;
    assert_eq!(first.total, Some(1));
    let work = tx.begin().await?;
    correlation_verdict::Entity::delete_many()
        .exec(&work)
        .await?;
    work.rollback().await?;
    assert_eq!(
        service
            .verdict_page(id, &ResolutionRequest::default(), page, &cache, &tx)
            .await?
            .items,
        first.items
    );
    tx.execute_raw(sql(
        "DELETE FROM correlation_evidence WHERE sbom_id=$1",
        vec![id.into()],
    ))
    .await?;
    tx.commit().await?;
    while run_step(&db).await? {}
    let tx = ctx.db.begin().await?;
    let empty = service
        .verdict_page(id, &ResolutionRequest::default(), page, &cache, &tx)
        .await?;
    assert_eq!(empty.total, Some(0));
    assert!(empty.items.is_empty());
    assert_ne!(empty.freshness.generation, first.freshness.generation);
    assert!(
        service
            .verdict_page(
                id,
                &ResolutionRequest::default(),
                Paginated { limit: 26, ..page },
                &cache,
                &tx
            )
            .await
            .is_err()
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn batched_computation_and_workers_preserve_complete_groups(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = fixture(ctx).await?;
    let tx = ctx.db.begin().await?;
    tx.execute_raw(sql("INSERT INTO sbom_node(sbom_id,node_id,name) SELECT $1,'batch-' || lpad(n::text,4,'0'),'Batch component' FROM generate_series(1,300) n",vec![id.into()])).await?;
    tx.execute_raw(sql("INSERT INTO correlation_evidence(id,sbom_id,node_id,advisory_id,vulnerability_id,status,confidence,extractor,matched_value,created_at,confidence_factors,source_assertions) SELECT gen_random_uuid(),e.sbom_id,'batch-' || lpad(n::text,4,'0'),advisory_id,vulnerability_id,status,confidence,extractor,matched_value,created_at,confidence_factors,source_assertions FROM correlation_evidence e CROSS JOIN generate_series(1,300) n WHERE sbom_id=$1",vec![id.into()])).await?;
    tx.commit().await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    // A claimed job is skipped; rolling its transaction back makes it available again.
    let claim = ctx.db.begin().await?;
    claim
        .query_one_raw(sql(
            "SELECT sbom_id FROM correlation_verdict_state WHERE sbom_id=$1 FOR UPDATE",
            vec![id.into()],
        ))
        .await?;
    assert!(!run_step(&db).await?);
    claim.rollback().await?;
    assert!(run_step(&db).await?);
    let tx = ctx.db.begin().await?;
    let service = CorrelationService::default();
    let cache = PaginationCache::for_test();
    let mut keys = Vec::new();
    for offset in (0..350).step_by(25) {
        let page = service
            .verdict_page(
                id,
                &ResolutionRequest::default(),
                Paginated {
                    offset,
                    limit: 25,
                    total: true,
                },
                &cache,
                &tx,
            )
            .await?;
        assert_eq!(page.total, Some(301));
        keys.extend(page.items.into_iter().map(|v| v.component.node_id));
    }
    assert_eq!(keys.len(), 301);
    assert!(keys.windows(2).all(|p| p[0] < p[1]));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn workers_skip_claimed_sboms_and_publish_other_work(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let first = fixture(ctx).await?;
    let second = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    drain_extraction(ctx).await?;
    let claim = ctx.db.begin().await?;
    claim
        .query_one_raw(sql(
            "SELECT sbom_id FROM sbom WHERE sbom_id=$1 FOR NO KEY UPDATE",
            vec![first.into()],
        ))
        .await?;
    claim
        .query_one_raw(sql(
            "SELECT sbom_id FROM correlation_verdict_state WHERE sbom_id=$1 FOR UPDATE",
            vec![first.into()],
        ))
        .await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(run_step(&db).await?);
    let states = state(&[first, second], &ctx.db).await?;
    assert!(states[&first].generation.is_none());
    assert!(states[&second].generation.is_some());
    claim.rollback().await?;
    assert!(run_step(&db).await?);
    assert!(state(&[first], &ctx.db).await?[&first].generation.is_some());
    Ok(())
}

/// Reproducible read-path scale check; run explicitly when changing the projection or indexes.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
#[ignore = "explicit read-path scale measurement"]
async fn published_page_scale(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let id = fixture(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    while run_step(&db).await? {}
    for size in [100_i32, 10_000] {
        let tx = ctx.db.begin().await?;
        tx.execute_raw(sql("INSERT INTO correlation_verdict(sbom_id,node_id,vulnerability_id,status,snapshot,remediation_count) SELECT sbom_id,'scale-'||lpad(n::text,6,'0'),vulnerability_id,status,snapshot,remediation_count FROM (SELECT * FROM correlation_verdict WHERE sbom_id=$1 LIMIT 1) sample CROSS JOIN generate_series(1,$2) n ON CONFLICT DO NOTHING",vec![id.into(),size.into()])).await?;
        tx.execute_unprepared("ANALYZE correlation_verdict").await?;
        let started = std::time::Instant::now();
        let page = CorrelationService::default()
            .verdict_page(
                id,
                &ResolutionRequest::default(),
                Paginated::default(),
                &PaginationCache::for_test(),
                &tx,
            )
            .await?;
        assert_eq!(page.items.len(), 25);
        let elapsed = started.elapsed();
        let plan = tx.query_one_raw(sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT snapshot FROM correlation_verdict WHERE sbom_id=$1 ORDER BY node_id,vulnerability_id LIMIT 25",vec![id.into()])).await?.unwrap();
        let plan: serde_json::Value = plan.try_get_by_index(0)?;
        assert!(plan.to_string().contains("correlation_verdict_pkey"));
        println!("{size} verdicts: page read {elapsed:?}; query plan {plan}");
        tx.commit().await?;
    }
    Ok(())
}
