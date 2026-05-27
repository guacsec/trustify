use crate::{
    config::AnalysisConfig,
    service::{
        AnalysisService, ComponentReference, QueryOptions, test::warnings::collect_warnings,
    },
};
use std::sync::Arc;
use test_context::test_context;
use trustify_common::model::{BinaryByteSize, Paginated};
use trustify_test_context::{IngestionResult, TrustifyContext};

/// Verify that cycle detection across external SBOM references works
/// regardless of cache pressure.
///
/// Two CycloneDX SBOMs form a cross-SBOM loop: A's component X has an
/// external dependency on B's component Y, and B's Y has an external
/// dependency back on A's X. With a large cache both graphs stay resident
/// and `DiscoveredTracker` detects the cycle via pointer identity. With a
/// tiny cache the graphs get evicted and re-loaded at new addresses —
/// exposing whether the tracker still catches the revisit.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn test_cache_eviction_cross_sbom_cycle_detection(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ctx.ingest_documents([
        "cyclonedx/loop-external/a.json",
        "cyclonedx/loop-external/b.json",
    ])
    .await?;

    let options = QueryOptions {
        descendants: u64::MAX,
        ..Default::default()
    };

    // --- large cache: both SBOMs fit comfortably ---

    let service_large = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let result_large = service_large
        .retrieve(
            ComponentReference::Name("X"),
            options.clone(),
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    let warnings_large = collect_warnings(&result_large.items);

    log::info!(
        "large cache: total={:?}, warnings={}",
        result_large.total,
        warnings_large.len()
    );

    // --- tiny cache: every SBOM is evicted immediately ---

    let service_tiny = AnalysisService::new(
        AnalysisConfig {
            max_cache_size: BinaryByteSize::from(1u64),
            ..Default::default()
        },
        ctx.db.clone(),
    );

    let result_tiny = service_tiny
        .retrieve(
            ComponentReference::Name("X"),
            options,
            Paginated::default(),
            &ctx.db,
        )
        .await?;

    let warnings_tiny = collect_warnings(&result_tiny.items);

    log::info!(
        "tiny cache: total={:?}, warnings={}",
        result_tiny.total,
        warnings_tiny.len()
    );

    // Both should detect the cross-SBOM cycle identically.
    assert_eq!(
        warnings_large.len(),
        warnings_tiny.len(),
        "cycle detection diverged under cache pressure: large cache produced {} warnings, tiny cache produced {}",
        warnings_large.len(),
        warnings_tiny.len(),
    );

    assert_eq!(
        result_large.total, result_tiny.total,
        "result count diverged under cache pressure",
    );

    Ok(())
}

/// Verify that loading the same SBOM twice under cache pressure returns
/// the same `Arc` handle, not two independent allocations.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn test_cache_eviction_same_handle(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_documents(["cyclonedx/loop-external/a.json"])
        .await?;
    let [sbom_uuid] = result.into_uuid();

    let service = AnalysisService::new(
        AnalysisConfig {
            max_cache_size: BinaryByteSize::from(1u64),
            ..Default::default()
        },
        ctx.db.clone(),
    );

    let first = service.load_graphs(&ctx.db, [sbom_uuid]).await?;
    let second = service.load_graphs(&ctx.db, [sbom_uuid]).await?;

    let first_arc = &first.first().expect("first load should return a graph").1;
    let second_arc = &second.first().expect("second load should return a graph").1;

    assert!(
        Arc::ptr_eq(first_arc, second_arc),
        "loading the same SBOM twice should return the same Arc handle, \
         but got two different allocations (cache eviction created a duplicate)",
    );

    Ok(())
}
