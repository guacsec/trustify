use crate::{
    config::AnalysisConfig,
    service::{
        AnalysisService, ComponentReference, QueryOptions, test::warnings::collect_warnings,
    },
};
use std::collections::BTreeMap;
use test_context::test_context;
use trustify_common::model::{BinaryByteSize, Paginated, PaginatedResults};
use trustify_test_context::TrustifyContext;

/// Given a set of ingested documents and a component query,
/// when the same query is run against a large cache and a tiny (1-byte) cache,
/// then the result counts and warning counts must be identical.
///
/// The 1-byte cache guarantees that every SBOM is evicted immediately after
/// loading, forcing the collector to re-load graphs from the database on
/// every access that isn't covered by its own local cache.
async fn assert_cache_pressure_invariant(
    ctx: &TrustifyContext,
    documents: &[&str],
    component: &str,
    options: QueryOptions,
) -> PaginatedResults<crate::model::Node> {
    ctx.ingest_documents(documents.iter().copied()).await.ok();

    let paginated = Paginated {
        total: true,
        ..Paginated::default()
    };

    // --- large cache: both SBOMs fit comfortably ---

    let service_large = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let result_large = service_large
        .retrieve(
            ComponentReference::Name(component),
            options.clone(),
            paginated,
            &ctx.db,
        )
        .await
        .expect("large-cache retrieve failed");

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
            ComponentReference::Name(component),
            options,
            paginated,
            &ctx.db,
        )
        .await
        .expect("tiny-cache retrieve failed");

    let warnings_tiny = collect_warnings(&result_tiny.items);

    log::info!(
        "tiny cache: total={:?}, warnings={}",
        result_tiny.total,
        warnings_tiny.len()
    );

    assert_eq!(
        result_large.total, result_tiny.total,
        "result count diverged under cache pressure",
    );

    let sorted_values = |warnings: &BTreeMap<_, &[String]>| -> Vec<String> {
        let mut v: Vec<_> = warnings.values().flat_map(|w| w.iter().cloned()).collect();
        v.sort();
        v
    };

    assert_eq!(
        sorted_values(&warnings_large),
        sorted_values(&warnings_tiny),
        "warnings diverged under cache pressure",
    );

    result_large
}

/// Two CycloneDX SBOMs form a cross-SBOM loop: A's component X has an
/// external dependency on B's component Y, and B's Y has an external
/// dependency back on A's X. With a large cache both graphs stay resident
/// and `DiscoveredTracker` detects the cycle. With a tiny cache the graphs
/// get evicted and reloaded — the UUID-based tracker must still detect
/// the revisit.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn cross_sbom_cycle(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert_cache_pressure_invariant(
        ctx,
        &[
            "cyclonedx/loop-external/a.json",
            "cyclonedx/loop-external/b.json",
        ],
        "X",
        QueryOptions {
            descendants: u64::MAX,
            ..Default::default()
        },
    )
    .await;

    Ok(())
}

/// Three components in one SBOM (C1, C2, C3) each have an external
/// dependency on the same component T1 in another SBOM. Verifies that
/// all three external references resolve correctly under cache pressure
/// and produce the same results as with a large cache.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn fan_out_same_target(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = assert_cache_pressure_invariant(
        ctx,
        &[
            "cyclonedx/fan-out-external/container.json",
            "cyclonedx/fan-out-external/target.json",
        ],
        "fan-out-container",
        QueryOptions {
            descendants: u64::MAX,
            ..Default::default()
        },
    )
    .await;

    let container = result
        .items
        .iter()
        .find(|n| n.node_id == "root")
        .expect("should have the root component node");

    let descendants = container
        .descendants
        .as_ref()
        .expect("root should have descendants");

    assert_eq!(descendants.len(), 3);

    let resolved_count = descendants
        .iter()
        .filter(|c| {
            c.descendants
                .as_ref()
                .is_some_and(|d| d.iter().any(|d| d.node_id.contains("t1")))
        })
        .count();

    assert_eq!(
        resolved_count, 3,
        "all 3 children should have resolved T1 from the external SBOM"
    );

    Ok(())
}
