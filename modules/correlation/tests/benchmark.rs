#![recursion_limit = "512"]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Instant;
use test_context::test_context;
use test_log::test;
use trustify_common::{db::pagination_cache::PaginationCache, id::Id};
use trustify_module_correlation::{config::CorrelationConfig, service::CorrelationService};
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::{Dataset, TrustifyContext};

/// Benchmark: compare v3 (SQL) vs v4 (in-memory) correlation for quarkus-bom.
///
/// Ingests the DS3 dataset, then runs both the v3 SQL-based correlation
/// and the v4 in-memory correlation on the quarkus-bom SBOM, timing each.
/// Also verifies that both produce the same advisory count.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_quarkus_bom(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let sbom = &result.files["spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2"];
    let sbom_id = Id::parse_uuid(&sbom.id)?;

    // --- v3 baseline (SQL) ---
    let sbom_service = SbomService::new(PaginationCache::for_test());

    let start_v3 = Instant::now();
    let v3_details = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");
    let v3_time = start_v3.elapsed();
    let v3_count = v3_details.advisories.len();

    log::info!(
        "v3 quarkus-bom: {} advisories in {}",
        v3_count,
        humantime::Duration::from(v3_time),
    );

    // --- v4 correlation (in-memory) ---
    let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
    let config = CorrelationConfig {
        correlation_enabled: true,
    };
    let correlation = CorrelationService::new(&config, db_ro).await?;

    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };

    let start_v4 = Instant::now();
    let v4_matches = correlation.correlate_sbom(sbom_uuid)?;
    let v4_time = start_v4.elapsed();

    // Count unique advisories from correlation matches
    let v4_advisory_ids: std::collections::HashSet<_> =
        v4_matches.iter().map(|m| m.advisory_id).collect();
    let v4_count = v4_advisory_ids.len();

    log::info!(
        "v4 quarkus-bom: {} advisories ({} matches) in {}",
        v4_count,
        v4_matches.len(),
        humantime::Duration::from(v4_time),
    );

    log::info!(
        "speedup: {:.1}x (v3={}, v4={})",
        v3_time.as_secs_f64() / v4_time.as_secs_f64(),
        humantime::Duration::from(v3_time),
        humantime::Duration::from(v4_time),
    );

    // Verify both find the same advisory count
    assert_eq!(
        v3_count, v4_count,
        "v3 found {} advisories but v4 found {} — mismatch!",
        v3_count, v4_count,
    );

    // Known DS3 ground truth: quarkus-bom should have 22 advisories
    assert_eq!(v3_count, 22, "expected 22 advisories for quarkus-bom");

    Ok(())
}

/// Benchmark: ubi8 SBOM correlation (fewer matches).
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_ubi8(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let sbom = &result.files["spdx/ubi8-8.8-1067.json.bz2"];
    let sbom_id = Id::parse_uuid(&sbom.id)?;

    // --- v3 baseline ---
    let sbom_service = SbomService::new(PaginationCache::for_test());

    let start_v3 = Instant::now();
    let v3_details = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");
    let v3_time = start_v3.elapsed();
    let v3_count = v3_details.advisories.len();

    log::info!(
        "v3 ubi8: {} advisories in {}",
        v3_count,
        humantime::Duration::from(v3_time),
    );

    // --- v4 correlation ---
    let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
    let config = CorrelationConfig {
        correlation_enabled: true,
    };
    let correlation = CorrelationService::new(&config, db_ro).await?;

    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };

    let start_v4 = Instant::now();
    let v4_matches = correlation.correlate_sbom(sbom_uuid)?;
    let v4_time = start_v4.elapsed();

    let v4_advisory_ids: std::collections::HashSet<_> =
        v4_matches.iter().map(|m| m.advisory_id).collect();
    let v4_count = v4_advisory_ids.len();

    log::info!(
        "v4 ubi8: {} advisories ({} matches) in {}",
        v4_count,
        v4_matches.len(),
        humantime::Duration::from(v4_time),
    );

    log::info!(
        "speedup: {:.1}x (v3={}, v4={})",
        v3_time.as_secs_f64() / v4_time.as_secs_f64(),
        humantime::Duration::from(v3_time),
        humantime::Duration::from(v4_time),
    );

    // Verify counts match
    assert_eq!(
        v3_count, v4_count,
        "v3 found {} advisories but v4 found {} — mismatch!",
        v3_count, v4_count,
    );

    // Known DS3 ground truth: ubi8 should have 1 advisory (CVE-2024-28834)
    assert_eq!(v3_count, 1, "expected 1 advisory for ubi8");

    Ok(())
}
