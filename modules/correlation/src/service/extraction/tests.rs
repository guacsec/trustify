use super::*;
use crate::extractor::{Extractor, NodeIdentifier, NodeMatch, worker::run_extraction_workers};
use std::num::NonZeroUsize;
use test_context::test_context;
use test_log::test;
use trustify_common::db::change::{
    ChangeBroadcaster, ChangeEntity, ChangeOperation, record_change,
};
use trustify_test_context::TrustifyContext;

async fn status(ctx: &TrustifyContext) -> anyhow::Result<ExtractionLag> {
    Ok(lag(&ctx.db.begin().await?).await?)
}

/// An NVD record, ingested without a format hint, is queued like any other advisory.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn nvd_advisory_is_queued(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("nvd/CVE-2024-6387.json").await?;
    let lag = status(ctx).await?;
    assert_eq!(
        lag,
        ExtractionLag {
            pending_advisories: 1,
            oldest_pending_at: lag.oldest_pending_at,
            ..ExtractionLag::default()
        }
    );
    assert!(lag.oldest_pending_at.is_some());
    Ok(())
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
        assert!(run_step(&db, &Extractors::new(vec![]), &WorkerConfig::default()).await?);
    }
    assert!(!run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
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
    // SBOMs are extracted by refresh jobs, not through the ingestion queue.
    ctx.ingest_document("spdx/simple.json").await?;
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
        _: Option<&[&str]>,
        _: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        Ok(vec![])
    }

    async fn match_advisory(
        &self,
        _: Uuid,
        tx: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
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
    let sbom = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    let failing = Extractors::new(vec![Box::new(FailingExtractor)]);
    assert!(run_step(&db, &failing, &WorkerConfig::default()).await?);
    let failed = status(ctx).await?;
    assert_eq!(
        failed,
        ExtractionLag {
            pending_advisories: 1,
            failed: 1,
            oldest_pending_at: Some(
                failed
                    .oldest_pending_at
                    .expect("pending work has an enqueue time")
            ),
            current: vec![],
        }
    );
    assert_eq!(
        freshness::for_sboms(&ctx.db.begin().await?, &[sbom]).await?[&sbom].status,
        crate::model::FreshnessStatus::Unknown
    );
    // Retry is delayed, preventing a bad document from spinning or starving others.
    assert!(!run_step(&db, &failing, &WorkerConfig::default()).await?);
    record_change(
        &ctx.db,
        ChangeEntity::Advisory,
        Some(Uuid::new_v4()),
        ChangeOperation::Added,
    )
    .await?;
    assert!(run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
    assert_eq!(status(ctx).await?, failed);
    ctx.db
        .execute_unprepared("UPDATE correlation_extraction_queue SET retry_at = clock_timestamp()")
        .await?;
    assert!(run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn claims_are_exclusive_and_deleted_documents_do_not_block_the_queue(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    let claim = ctx.db.begin().await?;
    claim
        .execute_unprepared("SELECT id FROM correlation_extraction_queue FOR UPDATE")
        .await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(!run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
    // An advisory deleted (or never stored) before processing has nothing to extract.
    record_change(
        &ctx.db,
        ChangeEntity::Advisory,
        Some(Uuid::new_v4()),
        ChangeOperation::Added,
    )
    .await?;
    // A second worker can handle another event while the first is claimed.
    assert!(run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
    let pending = status(ctx).await?;
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
    claim.rollback().await?;
    assert!(run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
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
        _: Option<&[&str]>,
        _: &DatabaseTransaction,
    ) -> Result<Vec<NodeIdentifier>, Error> {
        Ok(vec![])
    }

    async fn match_advisory(
        &self,
        _: Uuid,
        _: &DatabaseTransaction,
    ) -> Result<Vec<NodeMatch>, Error> {
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
    let advisory_id = Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
    let pending = status(ctx).await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let extractors = Extractors::new(vec![Box::new(PausedExtractor(barrier.clone()))]);
    let db = db::ReadWrite::new(ctx.db.clone());
    let worker =
        tokio::spawn(async move { run_step(&db, &extractors, &WorkerConfig::default()).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), barrier.wait()).await?;
    let running = status(ctx).await?;
    let started_at = running
        .current
        .first()
        .map(|current| current.started_at)
        .ok_or_else(|| anyhow::anyhow!("no current advisory"))?;
    assert_eq!(
        running,
        ExtractionLag {
            current: vec![CurrentAdvisory {
                advisory_id,
                identifier: "https://www.redhat.com/#CVE-2023-33201".into(),
                started_at,
            }],
            ..pending
        }
    );
    barrier.wait().await;
    assert!(worker.await??);
    assert_eq!(status(ctx).await?, ExtractionLag::default());
    Ok(())
}

/// A row left behind by a crashed worker isn't reported, and the next extraction replaces it.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn crashed_extraction_is_not_reported_as_running(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let advisory_id = Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
    ctx.db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO correlation_extraction_current(advisory_id, started_at) \
             VALUES ($1, now() - interval '2 hours')",
            vec![advisory_id.into()],
        ))
        .await?;
    assert_eq!(status(ctx).await?.current, vec![]);

    let db = db::ReadWrite::new(ctx.db.clone());
    assert!(run_step(&db, &Extractors::default(), &WorkerConfig::default()).await?);
    let rows = ctx
        .db
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT advisory_id FROM correlation_extraction_current",
        ))
        .await?;
    assert_eq!(rows.len(), 0);
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn worker_drains_ingestion_committed_before_it_subscribed(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    ctx.ingest_document("spdx/simple.json").await?;
    ctx.ingest_document("correlation/openssl_el8_newer.cdx.json")
        .await?;
    ctx.ingest_document("correlation/osv/hyper-0.14.1.cdx.json")
        .await?;
    ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    // Simulate a restart after notification history has already been cleaned up.
    ctx.db.execute_unprepared("DELETE FROM change_log").await?;
    let db = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = ChangeBroadcaster::new(
        &db,
        std::time::Duration::from_secs(86400),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(300),
    )?;
    let worker = tokio::spawn(run_extraction_workers(
        broadcaster,
        db,
        WorkerConfig {
            workers: NonZeroUsize::new(3).unwrap(),
            ..Default::default()
        },
    ));
    // The workers drain the advisory queue and refresh never-extracted SBOMs, sharing the job.
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while status(ctx).await? != ExtractionLag::default()
            || freshness::overview(&ctx.db.begin().await?)
                .await?
                .needs_refresh
                > 0
        {
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
