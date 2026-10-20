use super::*;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use test_context::test_context;
use test_log::test;
use trustify_entity::{correlation_evidence, sbom};
use trustify_test_context::TrustifyContext;

async fn ingest(ctx: &TrustifyContext) -> anyhow::Result<Uuid> {
    Ok(Uuid::parse_str(
        &ctx.ingest_document("spdx/simple.json").await?.id,
    )?)
}

async fn counts(ctx: &TrustifyContext) -> anyhow::Result<FreshnessOverview> {
    Ok(overview(&ctx.db.begin().await?).await?)
}

async fn option_change(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.db.execute_unprepared("UPDATE correlation_option SET value = to_jsonb(NOT (value::boolean)) WHERE publisher_namespace = 'https://www.redhat.com' AND key = 'versionless_purl'").await?;
    Ok(())
}

async fn queue(ctx: &TrustifyContext) -> anyhow::Result<RefreshJob> {
    let tx = ctx.db.begin().await?;
    let job = start(&tx).await?;
    tx.commit().await?;
    Ok(job)
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn completion_counts_include_zero_matches_and_deletions(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = ingest(ctx).await?;
    let initial = counts(ctx).await?;
    assert_eq!(
        (
            initial.total,
            initial.current,
            initial.unknown,
            initial.needs_refresh
        ),
        (1, 0, 1, 1)
    );
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    let done = counts(ctx).await?;
    assert_eq!(
        (done.total, done.current, done.unknown, done.needs_refresh),
        (1, 1, 0, 0)
    );
    assert_eq!(
        correlation_evidence::Entity::find()
            .filter(correlation_evidence::Column::SbomId.eq(id))
            .all(&ctx.db)
            .await?
            .len(),
        0
    );
    let tx = ctx.db.begin().await?;
    let current = for_sboms(&tx, &[id]).await?.remove(&id).unwrap();
    assert_eq!(current.status, FreshnessStatus::Current);
    assert!(current.completed_at.is_some());
    tx.rollback().await?;
    sbom::Entity::delete_by_id(id).exec(&ctx.db).await?;
    let deleted = counts(ctx).await?;
    assert_eq!(
        (deleted.total, deleted.current, deleted.needs_refresh),
        (0, 0, 0)
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn option_invalidation_and_description_changes(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let id = ingest(ctx).await?;
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    let original = counts(ctx).await?.revision;
    ctx.db
        .execute_unprepared("UPDATE correlation_option SET reason = 'description only'")
        .await?;
    assert_eq!(counts(ctx).await?.revision, original);
    option_change(ctx).await?;
    let stale = counts(ctx).await?;
    assert_eq!(stale.revision, original + 1);
    assert_eq!((stale.current, stale.stale, stale.needs_refresh), (0, 1, 1));
    let tx = ctx.db.begin().await?;
    assert_eq!(
        for_sboms(&tx, &[id]).await?[&id].status,
        FreshnessStatus::Stale
    );
    // A partial advisory extraction cannot promote an outdated SBOM.
    Extractors::default()
        .extract_for_advisory(Uuid::new_v4(), &tx)
        .await?;
    assert_eq!(
        for_sboms(&tx, &[id]).await?[&id].status,
        FreshnessStatus::Stale
    );
    tx.commit().await?;
    ctx.db.execute_unprepared("INSERT INTO correlation_option(id,key,publisher_namespace,value) VALUES ('00000000-0000-0000-0000-000000002680','versionless_purl','https://new.example','true')").await?;
    assert_eq!(counts(ctx).await?.revision, original + 2);
    ctx.db.execute_unprepared("UPDATE correlation_option SET publisher_namespace = 'https://renamed.example' WHERE publisher_namespace = 'https://new.example'").await?;
    assert_eq!(counts(ctx).await?.revision, original + 3);
    ctx.db.execute_unprepared("UPDATE correlation_option SET key = 'fixed_is_first_fixed' WHERE publisher_namespace = 'https://renamed.example'").await?;
    assert_eq!(counts(ctx).await?.revision, original + 4);
    ctx.db
        .execute_unprepared(
            "DELETE FROM correlation_option WHERE publisher_namespace = 'https://renamed.example'",
        )
        .await?;
    assert_eq!(counts(ctx).await?.revision, original + 5);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn durable_jobs_are_deduplicated_and_resumable(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let id = ingest(ctx).await?;
    let queued = queue(ctx).await?;
    assert_eq!(queued.id, queue(ctx).await?.id);
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(run_step(&db, &Extractors::default()).await?);
    // A new registry/worker instance resumes from the committed job cursor.
    assert!(!run_step(&db, &Extractors::default()).await?);
    let tx = ctx.db.begin().await?;
    let details = job(&tx, queued.id, Paginated::default()).await?;
    assert_eq!(details.job.status, RefreshJobStatus::Completed);
    assert_eq!((details.job.processed, details.job.failed), (1, 0));
    assert_eq!(
        for_sboms(&tx, &[id]).await?[&id].status,
        FreshnessStatus::Current
    );
    tx.rollback().await?;
    assert_eq!(counts(ctx).await?.needs_refresh, 0);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn concurrent_workers_skip_claimed_jobs_and_traverse_revision_buckets(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let first = ingest(ctx).await?;
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), first, &tx).await?;
    tx.commit().await?;
    option_change(ctx).await?;
    ctx.ingest_document("correlation/openssl_el8_newer.cdx.json")
        .await?;
    let queued = queue(ctx).await?;
    let claim = ctx.db.begin().await?;
    claim
        .query_one_raw(sql(
            "SELECT id FROM correlation_refresh_job WHERE id = $1 FOR UPDATE",
            vec![queued.id.into()],
        ))
        .await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(!run_step(&db, &Extractors::default()).await?);
    claim.rollback().await?;
    assert!(run_step(&db, &Extractors::default()).await?);
    assert!(run_step(&db, &Extractors::default()).await?);
    assert!(!run_step(&db, &Extractors::default()).await?);
    let state = counts(ctx).await?;
    assert_eq!((state.current, state.stale, state.unknown), (2, 0, 0));
    let tx = ctx.db.begin().await?;
    assert_eq!(
        job(&tx, queued.id, Paginated::default())
            .await?
            .job
            .processed,
        2
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn changed_settings_supersede_a_job(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ingest(ctx).await?;
    let queued = queue(ctx).await?;
    option_change(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(!run_step(&db, &Extractors::default()).await?);
    let tx = ctx.db.begin().await?;
    let details = job(&tx, queued.id, Paginated::default()).await?;
    assert_eq!(details.job.status, RefreshJobStatus::Superseded);
    assert_eq!(details.job.processed, 0);
    tx.rollback().await?;
    assert_ne!(queue(ctx).await?.id, queued.id);
    Ok(())
}

struct FailingExtractor;
#[async_trait::async_trait]
impl crate::extractor::Extractor for FailingExtractor {
    fn id(&self) -> &'static str {
        "test_failure"
    }
    async fn sbom_identifiers(
        &self,
        _: Uuid,
        _: &DatabaseTransaction,
    ) -> Result<Vec<crate::extractor::NodeIdentifier>, Error> {
        Err(Error::BadRequest("deliberate extraction failure".into()))
    }
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn failed_jobs_preserve_evidence_and_can_be_retried(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    use sea_orm::{ActiveModelTrait, Set};
    let id = ingest(ctx).await?;
    let advisory = Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
    let evidence = correlation_evidence::ActiveModel {
        id: Set(Uuid::new_v4()),
        sbom_id: Set(id),
        node_id: Set("SPDXRef-Package".into()),
        advisory_id: Set(advisory),
        vulnerability_id: Set("CVE-2023-33201".into()),
        status: Set(correlation_evidence::AssertionStatus::Affected),
        confidence: Set(0.1),
        extractor: Set("obsolete".into()),
        matched_value: Set(None),
        created_at: Set(OffsetDateTime::now_utc()),
        confidence_factors: Set(serde_json::json!([])),
        source_assertions: Set(serde_json::json!([])),
    }
    .insert(&ctx.db)
    .await?;
    let queued = queue(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    let failing = Extractors::new(vec![Box::new(FailingExtractor)]);
    assert!(run_step(&db, &failing).await?);
    assert!(!run_step(&db, &failing).await?);
    assert!(
        correlation_evidence::Entity::find_by_id(evidence.id)
            .one(&ctx.db)
            .await?
            .is_some()
    );
    let tx = ctx.db.begin().await?;
    let details = job(&tx, queued.id, Paginated::default()).await?;
    assert_eq!(
        (
            details.job.processed,
            details.job.failed,
            details.failures.len()
        ),
        (0, 1, 1)
    );
    assert_eq!(
        for_sboms(&tx, &[id]).await?[&id].status,
        FreshnessStatus::Unknown
    );
    tx.rollback().await?;
    assert_ne!(queue(ctx).await?.id, queued.id);
    assert!(run_step(&db, &Extractors::default()).await?);
    assert!(!run_step(&db, &Extractors::default()).await?);
    assert!(
        correlation_evidence::Entity::find_by_id(evidence.id)
            .one(&ctx.db)
            .await?
            .is_none()
    );
    assert_eq!(counts(ctx).await?.needs_refresh, 0);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn extraction_locks_settings_and_document_writes(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = ingest(ctx).await?;
    let first = ctx.db.begin().await?;
    lock_revision(&first).await?;
    lock_sboms(&first, vec![id]).await?;
    let other = ctx.db.begin().await?;
    other
        .execute_unprepared("SET LOCAL lock_timeout = '50ms'")
        .await?;
    assert!(lock_sboms(&other, vec![id]).await.is_err());
    other.rollback().await?;
    let option = ctx.db.begin().await?;
    option
        .execute_unprepared("SET LOCAL lock_timeout = '50ms'")
        .await?;
    assert!(option.execute_unprepared("UPDATE correlation_option SET value = 'false' WHERE key = 'versionless_purl' AND publisher_namespace = 'https://www.redhat.com'").await.is_err());
    option.rollback().await?;
    first.rollback().await?;
    option_change(ctx).await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn lists_include_unknowns_and_honor_pagination(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let id = ingest(ctx).await?;
    let tx = ctx.db.begin().await?;
    let page = documents(
        &tx,
        None,
        Paginated {
            offset: 0,
            limit: 1,
            total: true,
        },
    )
    .await?;
    assert_eq!(page.total, Some(1));
    assert_eq!(page.items[0].sbom_id, id);
    assert_eq!(page.items[0].freshness.status, FreshnessStatus::Unknown);
    assert_eq!(
        documents(
            &tx,
            None,
            Paginated {
                offset: 1,
                limit: 1,
                total: true
            }
        )
        .await?
        .items
        .len(),
        0
    );
    assert!(
        documents(&tx, Some(FreshnessStatus::Current), Paginated::default())
            .await?
            .items
            .is_empty()
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn refresh_replaces_changed_evidence_and_finds_new_matches(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = Uuid::parse_str(
        &ctx.ingest_document(
            "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
        )
        .await?
        .id,
    )?;
    ctx.ingest_document("scenarios/S5_positive_baseline_openssl_el8/vex/CVE-2023-0215.json.xz")
        .await?;
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    let original = correlation_evidence::Entity::find().all(&ctx.db).await?;
    assert!(!original.is_empty());
    ctx.db.execute_unprepared("UPDATE correlation_evidence SET confidence = 0.01, confidence_factors = '[]', matched_value = jsonb_set(matched_value, '{ranges}', '[]') ").await?;
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    let restored = correlation_evidence::Entity::find().all(&ctx.db).await?;
    assert_eq!(restored.len(), original.len());
    for old in &original {
        let new = restored.iter().find(|r| r.id == old.id).unwrap();
        assert_eq!(new.confidence, old.confidence);
        assert_eq!(new.confidence_factors, old.confidence_factors);
        assert_eq!(new.matched_value, old.matched_value);
    }
    ctx.db.execute_unprepared("UPDATE correlation_option SET value = 'false' WHERE key = 'fixed_is_first_fixed' AND publisher_namespace = 'https://www.redhat.com'").await?;
    assert_eq!(counts(ctx).await?.stale, 1);
    let reader = ctx.db.begin().await?;
    reader
        .execute_unprepared("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .await?;
    assert_eq!(
        for_sboms(&reader, &[id]).await?[&id].status,
        FreshnessStatus::Stale
    );
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    // A response already being read cannot attach new freshness to its old evidence.
    assert_eq!(
        for_sboms(&reader, &[id]).await?[&id].status,
        FreshnessStatus::Stale
    );
    assert_eq!(
        correlation_evidence::Entity::find()
            .all(&reader)
            .await?
            .len(),
        original.len()
    );
    reader.rollback().await?;
    assert!(
        correlation_evidence::Entity::find()
            .all(&ctx.db)
            .await?
            .is_empty()
    );
    assert!(
        trustify_entity::correlation_evidence_context::Entity::find()
            .all(&ctx.db)
            .await?
            .is_empty()
    );
    ctx.db.execute_unprepared("UPDATE correlation_option SET value = 'true' WHERE key = 'fixed_is_first_fixed' AND publisher_namespace = 'https://www.redhat.com'").await?;
    queue(ctx).await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(run_step(&db, &Extractors::default()).await?);
    assert!(!run_step(&db, &Extractors::default()).await?);
    assert_eq!(
        correlation_evidence::Entity::find()
            .all(&ctx.db)
            .await?
            .len(),
        original.len()
    );
    assert_eq!(counts(ctx).await?.current, 1);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn metadata_migration_preserves_documents_and_resets_to_unknown(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = ingest(ctx).await?;
    let tx = ctx.db.begin().await?;
    refresh_sbom(&Extractors::default(), id, &tx).await?;
    tx.commit().await?;
    ctx.db
        .execute_unprepared(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migration/src/m0002680_correlation_freshness/down.sql"
        )))
        .await?;
    assert!(sbom::Entity::find_by_id(id).one(&ctx.db).await?.is_some());
    ctx.db
        .execute_unprepared(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../migration/src/m0002680_correlation_freshness/up.sql"
        )))
        .await?;
    let state = counts(ctx).await?;
    assert_eq!((state.total, state.unknown, state.current), (1, 1, 0));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn overview_uses_counters_and_discovery_can_use_the_completion_index(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ingest(ctx).await?;
    let tx = ctx.db.begin().await?;
    let row = tx
        .query_one_raw(sql(
            &format!("EXPLAIN (FORMAT JSON) {OVERVIEW_COUNTS_SQL}"),
            vec![],
        ))
        .await?
        .unwrap();
    let plan: serde_json::Value = row.try_get_by_index(0)?;
    let plan = plan.to_string();
    assert!(plan.contains("correlation_extraction_count"));
    assert!(!plan.contains("correlation_evidence"));
    assert!(!plan.contains("\"Relation Name\":\"sbom\""));
    assert!(!plan.contains("correlation_extraction_state"));
    tx.execute_unprepared("SET LOCAL enable_seqscan = off")
        .await?;
    let row = tx
        .query_one_raw(sql(
            &format!("EXPLAIN (FORMAT JSON) {NEXT_DOCUMENT_SQL}"),
            vec![
                1_i64.into(),
                Option::<Uuid>::None.into(),
                Option::<i64>::None.into(),
            ],
        ))
        .await?
        .unwrap();
    let plan: serde_json::Value = row.try_get_by_index(0)?;
    assert!(
        plan.to_string()
            .contains("correlation_extraction_state_revision")
    );
    Ok(())
}
