use super::*;
use crate::extractor::{Extractor, NodeIdentifier};
use test_context::test_context;
use test_log::test;
use trustify_common::db::change::{ChangeEntity, ChangeOperation, record_change};
use trustify_test_context::TrustifyContext;

async fn status(ctx: &TrustifyContext) -> anyhow::Result<ExtractionLag> {
    Ok(lag(&ctx.db.begin().await?).await?)
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn two_thousand_advisories_remain_pending_until_extraction_commits(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
    let tx = ctx.db.begin().await?;
    // Each committed ingestion event needs acknowledgement, even for an advisory
    // already seen before. A zero-match extraction must clear it too.
    for _ in 1..2000 {
        record_change(
            &tx,
            ChangeEntity::Advisory,
            Some(id),
            ChangeOperation::Added,
        )
        .await?;
    }
    tx.commit().await?;
    let before = status(ctx).await?;
    assert_eq!(
        before,
        ExtractionLag {
            pending_advisories: 2000,
            oldest_pending_at: Some(
                before
                    .oldest_pending_at
                    .expect("pending work has an enqueue time")
            ),
            ..ExtractionLag::default()
        }
    );
    // Work survives retention cleanup and does not depend on event delivery.
    ctx.db.execute_unprepared("DELETE FROM change_log").await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    for _ in 0..2000 {
        // A fresh registry simulates the absence of any in-memory job state.
        assert!(run_step(&db, &Extractors::new(vec![])).await?);
    }
    assert!(!run_step(&db, &Extractors::default()).await?);
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn enqueue_is_atomic_and_ignores_deletion_and_unknown_ids(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let tx = ctx.db.begin().await?;
    record_change(
        &tx,
        ChangeEntity::Advisory,
        Some(Uuid::new_v4()),
        ChangeOperation::Added,
    )
    .await?;
    let pending = lag(&tx).await?;
    assert_eq!(
        pending,
        ExtractionLag {
            pending_advisories: 1,
            oldest_pending_at: Some(
                pending
                    .oldest_pending_at
                    .expect("pending work has an enqueue time")
            ),
            ..ExtractionLag::default()
        }
    );
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    tx.rollback().await?;
    record_change(
        &ctx.db,
        ChangeEntity::Advisory,
        None,
        ChangeOperation::Added,
    )
    .await?;
    record_change(
        &ctx.db,
        ChangeEntity::Sbom,
        Some(Uuid::new_v4()),
        ChangeOperation::Deleted,
    )
    .await?;
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

struct FailingExtractor;

#[async_trait::async_trait]
impl Extractor for FailingExtractor {
    fn id(&self) -> &'static str {
        "failing"
    }

    async fn sbom_identifiers(
        &self,
        _: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        // This mutation must roll back with the failed extraction.
        tx.execute_unprepared("UPDATE correlation_extraction_state SET completed_revision = 99")
            .await?;
        Err(Error::BadRequest("deliberate extraction failure".into()))
    }
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn failures_stay_in_lag_and_retry_without_partial_completion(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    let db = db::ReadWrite::new(ctx.db.clone());
    let failing = Extractors::new(vec![Box::new(FailingExtractor)]);
    assert!(run_step(&db, &failing).await?);
    let failed = status(ctx).await?;
    assert_eq!(
        failed,
        ExtractionLag {
            pending_sboms: 1,
            failed: 1,
            oldest_pending_at: Some(
                failed
                    .oldest_pending_at
                    .expect("pending work has an enqueue time")
            ),
            ..ExtractionLag::default()
        }
    );
    assert_eq!(
        freshness::for_sboms(&ctx.db.begin().await?, &[id]).await?[&id].status,
        crate::model::FreshnessStatus::Unknown
    );
    // Retry is delayed, preventing a bad document from spinning or starving others.
    assert!(!run_step(&db, &failing).await?);
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    assert!(run_step(&db, &Extractors::default()).await?);
    assert_eq!(status(ctx).await?, failed);
    ctx.db
        .execute_unprepared("UPDATE correlation_extraction_queue SET retry_at = clock_timestamp()")
        .await?;
    assert!(run_step(&db, &Extractors::default()).await?);
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    assert_eq!(
        freshness::for_sboms(&ctx.db.begin().await?, &[id]).await?[&id].status,
        crate::model::FreshnessStatus::Current
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn claims_are_exclusive_and_deleted_documents_do_not_block_the_queue(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let id = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    let claim = ctx.db.begin().await?;
    claim
        .execute_unprepared("SELECT id FROM correlation_extraction_queue FOR UPDATE")
        .await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(!run_step(&db, &Extractors::default()).await?);
    record_change(
        &ctx.db,
        ChangeEntity::Advisory,
        Some(Uuid::new_v4()),
        ChangeOperation::Added,
    )
    .await?;
    // A second worker can handle another event while the first is claimed.
    assert!(run_step(&db, &Extractors::default()).await?);
    let pending = status(ctx).await?;
    assert_eq!(
        pending,
        ExtractionLag {
            pending_sboms: 1,
            oldest_pending_at: Some(
                pending
                    .oldest_pending_at
                    .expect("pending work has an enqueue time")
            ),
            ..ExtractionLag::default()
        }
    );
    claim.rollback().await?;
    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM sbom WHERE sbom_id = $1",
            vec![id.into()],
        ))
        .await?;
    assert!(run_step(&db, &Extractors::default()).await?);
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

struct PausedExtractor(std::sync::Arc<tokio::sync::Barrier>);

#[async_trait::async_trait]
impl Extractor for PausedExtractor {
    fn id(&self) -> &'static str {
        "paused"
    }

    async fn sbom_identifiers(
        &self,
        _: Uuid,
        _: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        self.0.wait().await;
        self.0.wait().await;
        Ok(vec![])
    }
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn running_extraction_stays_visible_until_evidence_and_acknowledgement_commit(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("spdx/simple.json").await?;
    let pending = status(ctx).await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let extractors = Extractors::new(vec![Box::new(PausedExtractor(barrier.clone()))]);
    let db = db::ReadWrite::new(ctx.db.clone());
    let worker = tokio::spawn(async move { run_step(&db, &extractors).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), barrier.wait()).await?;
    assert_eq!(status(ctx).await?, pending);
    barrier.wait().await;
    assert!(worker.await??);
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn worker_drains_ingestion_committed_before_it_subscribed(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("spdx/simple.json").await?;
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    // Simulate a restart after notification history has already been cleaned up.
    ctx.db.execute_unprepared("DELETE FROM change_log").await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = trustify_common::db::change::ChangeBroadcaster::new(
        &db,
        std::time::Duration::from_secs(86400),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(300),
    )?;
    let worker = tokio::spawn(crate::extractor::worker::run_extraction_worker(
        broadcaster,
        db,
    ));
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while status(ctx).await? != ExtractionLag::default() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        anyhow::Ok(())
    })
    .await;
    worker.abort();
    result??;
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn migration_backfills_existing_documents_and_can_be_reverted(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("spdx/simple.json").await?;
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    while run_step(&db, &Extractors::new(vec![])).await? {}
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    let tx = ctx.db.begin().await?;
    tx.execute_unprepared(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migration/src/m0002700_correlation_extraction_queue/down.sql"
    )))
    .await?;
    tx.execute_unprepared(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migration/src/m0002700_correlation_extraction_queue/up.sql"
    )))
    .await?;
    tx.commit().await?;
    let backfilled = status(ctx).await?;
    assert_eq!(
        backfilled,
        ExtractionLag {
            pending_advisories: 1,
            pending_sboms: 1,
            oldest_pending_at: Some(
                backfilled
                    .oldest_pending_at
                    .expect("pending work has an enqueue time")
            ),
            ..ExtractionLag::default()
        }
    );
    while run_step(&db, &Extractors::default()).await? {}
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}
