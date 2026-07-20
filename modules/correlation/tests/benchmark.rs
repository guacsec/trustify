#![recursion_limit = "512"]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use std::time::Instant;
use test_context::test_context;
use test_log::test;
use trustify_common::{db::pagination_cache::PaginationCache, id::Id, purl::Purl};
use trustify_module_correlation::{config::CorrelationConfig, service::CorrelationService};
use trustify_module_fundamental::{
    purl::service::PurlService, sbom::service::SbomService,
    vulnerability::service::VulnerabilityService,
};
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::{Dataset, TrustifyContext};

/// Benchmark: compare v3a (SQL) vs v3 (in-memory) correlation for quarkus-bom.
///
/// Ingests the DS3 dataset, then runs both the v3a SQL-based correlation
/// and the v3 in-memory correlation on the quarkus-bom SBOM, timing each.
/// Also verifies that both produce the same advisory count.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_quarkus_bom(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let sbom = &result.files["spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2"];
    let sbom_id = Id::parse_uuid(&sbom.id)?;

    // --- v3a baseline (SQL) ---
    let sbom_service = SbomService::new(PaginationCache::for_test());

    let start_v3a = Instant::now();
    let v3a_details = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");
    let v3a_time = start_v3a.elapsed();
    let v3a_count = v3a_details.advisories.len();

    log::info!(
        "v3a quarkus-bom: {} advisories in {}",
        v3a_count,
        humantime::Duration::from(v3a_time),
    );

    // --- v3 correlation (in-memory) ---
    let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
    let db_rw = trustify_common::db::ReadWrite::new(ctx.db.clone());
    let config = CorrelationConfig {
        correlation_poll_interval_secs: 30,
        correlation_debounce_secs: 2,
    };
    let correlation = CorrelationService::new(&config, db_ro, &db_rw).await?;

    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };

    let start_v3_correlate = Instant::now();
    let v3_matches = correlation.correlate_sbom(sbom_uuid)?;
    let v3_correlate_time = start_v3_correlate.elapsed();
    let match_count = v3_matches.len();

    // Hydrate: convert matches to Vec<SbomAdvisory> (includes DB lookups)
    let statuses = correlation.status_slugs();
    let txn = ctx.db.begin().await?;

    let start_v3_hydrate = Instant::now();
    let v3_advisories =
        trustify_module_correlation::service::hydrate::hydrate_matches(v3_matches, &statuses, &txn)
            .await?;
    let v3_hydrate_time = start_v3_hydrate.elapsed();

    let v3_total_time = v3_correlate_time + v3_hydrate_time;
    let v3_count = v3_advisories.len();

    log::info!(
        "v3 quarkus-bom: {} advisories ({} matches) — correlate={}, hydrate={}, total={}",
        v3_count,
        match_count,
        humantime::Duration::from(v3_correlate_time),
        humantime::Duration::from(v3_hydrate_time),
        humantime::Duration::from(v3_total_time),
    );

    log::info!(
        "speedup: {:.1}x (v3a={}, v3={})",
        v3a_time.as_secs_f64() / v3_total_time.as_secs_f64(),
        humantime::Duration::from(v3a_time),
        humantime::Duration::from(v3_total_time),
    );

    // Verify both find the same advisory count
    assert_eq!(
        v3a_count, v3_count,
        "v3a found {} advisories but v3 found {} — mismatch!",
        v3a_count, v3_count,
    );

    // Known DS3 ground truth: quarkus-bom should have 22 advisories
    assert_eq!(v3a_count, 22, "expected 22 advisories for quarkus-bom");

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

    // --- v3a baseline ---
    let sbom_service = SbomService::new(PaginationCache::for_test());

    let start_v3a = Instant::now();
    let v3a_details = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");
    let v3a_time = start_v3a.elapsed();
    let v3a_count = v3a_details.advisories.len();

    log::info!(
        "v3a ubi8: {} advisories in {}",
        v3a_count,
        humantime::Duration::from(v3a_time),
    );

    // --- v3 correlation ---
    let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
    let db_rw = trustify_common::db::ReadWrite::new(ctx.db.clone());
    let config = CorrelationConfig {
        correlation_poll_interval_secs: 30,
        correlation_debounce_secs: 2,
    };
    let correlation = CorrelationService::new(&config, db_ro, &db_rw).await?;

    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };

    let start_v3_correlate = Instant::now();
    let v3_matches = correlation.correlate_sbom(sbom_uuid)?;
    let v3_correlate_time = start_v3_correlate.elapsed();
    let match_count = v3_matches.len();

    let statuses = correlation.status_slugs();
    let txn = ctx.db.begin().await?;

    let start_v3_hydrate = Instant::now();
    let v3_advisories =
        trustify_module_correlation::service::hydrate::hydrate_matches(v3_matches, &statuses, &txn)
            .await?;
    let v3_hydrate_time = start_v3_hydrate.elapsed();

    let v3_total_time = v3_correlate_time + v3_hydrate_time;
    let v3_count = v3_advisories.len();

    log::info!(
        "v3 ubi8: {} advisories ({} matches) — correlate={}, hydrate={}, total={}",
        v3_count,
        match_count,
        humantime::Duration::from(v3_correlate_time),
        humantime::Duration::from(v3_hydrate_time),
        humantime::Duration::from(v3_total_time),
    );

    log::info!(
        "speedup: {:.1}x (v3a={}, v3={})",
        v3a_time.as_secs_f64() / v3_total_time.as_secs_f64(),
        humantime::Duration::from(v3a_time),
        humantime::Duration::from(v3_total_time),
    );

    // Verify counts match
    assert_eq!(
        v3a_count, v3_count,
        "v3a found {} advisories but v3 found {} — mismatch!",
        v3a_count, v3_count,
    );

    // Known DS3 ground truth: ubi8 should have 1 advisory (CVE-2024-28834)
    assert_eq!(v3a_count, 1, "expected 1 advisory for ubi8");

    Ok(())
}

/// Helper: creates a CorrelationService from a TrustifyContext.
async fn create_correlation(ctx: &TrustifyContext) -> anyhow::Result<CorrelationService> {
    let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
    let db_rw = trustify_common::db::ReadWrite::new(ctx.db.clone());
    let config = CorrelationConfig {
        correlation_poll_interval_secs: 30,
        correlation_debounce_secs: 2,
    };
    CorrelationService::new(&config, db_ro, &db_rw).await
}

/// Benchmark: compare v3a (SQL) vs v3 (in-memory) vulnerability details.
///
/// Uses CVE-2023-4853 from DS3, which has CSAF advisory data and affects
/// multiple packages in the quarkus-bom SBOM.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_vulnerability(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let vuln_id = "CVE-2023-4853";

    // --- v3a baseline (SQL) ---
    let vuln_service = VulnerabilityService::new(PaginationCache::for_test());

    let start_v3a = Instant::now();
    let v3a_details = vuln_service
        .fetch_vulnerability(vuln_id, Deprecation::Ignore, true, &ctx.db)
        .await?
        .expect("vulnerability should exist");
    let v3a_time = start_v3a.elapsed();
    let v3a_count = v3a_details.advisories.len();

    log::info!(
        "v3a vulnerability {}: {} advisories in {}",
        vuln_id,
        v3a_count,
        humantime::Duration::from(v3a_time),
    );

    // --- v3 correlation (in-memory) ---
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;

    let start_v3 = Instant::now();
    let matches = correlation.correlate_vulnerability(vuln_id)?;
    let vuln_entries = correlation.vulnerability_entries(vuln_id);
    let statuses = correlation.status_slugs();

    let vuln = trustify_entity::vulnerability::Entity::find_by_id(vuln_id)
        .one(&txn)
        .await?
        .expect("vulnerability should exist");

    let (advisory_vulns, vuln_scores) = tokio::try_join!(
        trustify_entity::advisory_vulnerability::Entity::find()
            .filter(trustify_entity::advisory_vulnerability::Column::VulnerabilityId.eq(vuln_id),)
            .all(&txn),
        trustify_entity::advisory_vulnerability_score::Entity::find()
            .filter(
                trustify_entity::advisory_vulnerability_score::Column::VulnerabilityId.eq(vuln_id),
            )
            .all(&txn),
    )?;

    let advisories =
        trustify_module_correlation::service::hydrate::hydrate_vulnerability_advisories(
            &vuln,
            &advisory_vulns,
            &vuln_scores,
            matches,
            &vuln_entries,
            &statuses,
            &txn,
        )
        .await?;
    let v3_time = start_v3.elapsed();
    let v3_count = advisories.len();

    log::info!(
        "v3 vulnerability {}: {} advisories in {}",
        vuln_id,
        v3_count,
        humantime::Duration::from(v3_time),
    );

    log::info!(
        "speedup: {:.1}x (v3a={}, v3={})",
        v3a_time.as_secs_f64() / v3_time.as_secs_f64(),
        humantime::Duration::from(v3a_time),
        humantime::Duration::from(v3_time),
    );

    assert_eq!(
        v3a_count, v3_count,
        "v3a found {} advisories but v3 found {} — mismatch!",
        v3a_count, v3_count,
    );

    Ok(())
}

/// Benchmark: compare v3a (SQL) vs v3 (in-memory) PURL detail lookup.
///
/// Uses a quarkus PURL from DS3 that has known advisory matches.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_purl(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purl_str = "pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar";
    let purl = Purl::try_from(purl_str)?;

    // --- v3a baseline (SQL) ---
    let purl_service = PurlService::new(PaginationCache::for_test());

    let start_v3a = Instant::now();
    let v3a_details = purl_service
        .purl_by_purl(&purl, Deprecation::Ignore, &ctx.db)
        .await?
        .expect("PURL should exist");
    let v3a_time = start_v3a.elapsed();
    let v3a_count = v3a_details.advisories.len();

    log::info!(
        "v3a purl: {} advisories in {}",
        v3a_count,
        humantime::Duration::from(v3a_time),
    );

    // --- v3 correlation (in-memory) ---
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;

    let start_v3 = Instant::now();
    let matches = correlation.correlate_purls(&[purl])?;
    let statuses = correlation.status_slugs();
    let purl_matches = matches.into_values().next().unwrap_or_default();
    let advisories = trustify_module_correlation::service::hydrate::hydrate_purl_advisories(
        purl_matches,
        &statuses,
        &txn,
    )
    .await?;
    let v3_time = start_v3.elapsed();
    let v3_count = advisories.len();

    log::info!(
        "v3 purl: {} advisories in {}",
        v3_count,
        humantime::Duration::from(v3_time),
    );

    log::info!(
        "speedup: {:.1}x (v3a={}, v3={})",
        v3a_time.as_secs_f64() / v3_time.as_secs_f64(),
        humantime::Duration::from(v3a_time),
        humantime::Duration::from(v3_time),
    );

    assert_eq!(
        v3a_count, v3_count,
        "v3a found {} advisories but v3 found {} — mismatch!",
        v3a_count, v3_count,
    );

    Ok(())
}

/// Benchmark: compare v3a (SQL) vs v3 (in-memory) vulnerability analysis.
///
/// Sends a batch of PURLs from the quarkus-bom through the analyze endpoint
/// and compares SQL-based analysis with in-memory correlation.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_analyze(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purls = [
        "pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?type=jar",
        "pkg:maven/io.netty/netty-handler@4.1.86.Final-redhat-00001?type=jar",
        "pkg:maven/org.apache.james/apache-mime4j-core@0.8.9-redhat-00001?type=jar",
    ];

    // --- v3a baseline (SQL) ---
    let vuln_service = VulnerabilityService::new(PaginationCache::for_test());

    let start_v3a = Instant::now();
    let v3a_response = vuln_service
        .analyze_purls_v3(purls.iter().copied(), &ctx.db)
        .await?;
    let v3a_time = start_v3a.elapsed();
    let v3a_count = v3a_response.0.len();

    log::info!(
        "v3a analyze: {} results in {}",
        v3a_count,
        humantime::Duration::from(v3a_time),
    );

    // --- v3 correlation (in-memory) ---
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;

    let parsed: Vec<_> = purls
        .iter()
        .filter_map(|p| Purl::try_from(*p).ok())
        .collect();

    let start_v3 = Instant::now();
    let matches = correlation.correlate_purls(&parsed)?;
    let statuses = correlation.status_slugs();
    let v3_response =
        trustify_module_correlation::service::hydrate::hydrate_analysis(matches, &statuses, &txn)
            .await?;
    let v3_time = start_v3.elapsed();
    let v3_count = v3_response.0.len();

    log::info!(
        "v3 analyze: {} results in {}",
        v3_count,
        humantime::Duration::from(v3_time),
    );

    log::info!(
        "speedup: {:.1}x (v3a={}, v3={})",
        v3a_time.as_secs_f64() / v3_time.as_secs_f64(),
        humantime::Duration::from(v3a_time),
        humantime::Duration::from(v3_time),
    );

    assert_eq!(
        v3a_count, v3_count,
        "v3a found {} results but v3 found {} — mismatch!",
        v3a_count, v3_count,
    );

    Ok(())
}

/// Benchmark: compare v3a (SQL) vs v3 (in-memory) PURL recommend.
///
/// Sends PURLs with known Red Hat patch versions through the recommend
/// path and compares the SQL-based and in-memory correlation results.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn benchmark_recommend(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purl_strs = ["pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?type=jar"];
    let purls: Vec<_> = purl_strs
        .iter()
        .filter_map(|p| Purl::try_from(*p).ok())
        .collect();

    // --- v3a baseline (SQL) ---
    let purl_service = PurlService::new(PaginationCache::for_test());

    let start_v3a = Instant::now();
    let v3a_result = purl_service.recommend_purls(&purls, &ctx.db).await?;
    let v3a_time = start_v3a.elapsed();
    let v3a_count: usize = v3a_result.values().map(|v| v.len()).sum();

    log::info!(
        "v3a recommend: {} entries across {} purls in {}",
        v3a_count,
        v3a_result.len(),
        humantime::Duration::from(v3a_time),
    );

    // --- v3 correlation (in-memory) ---
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;

    let start_v3 = Instant::now();
    let matches = correlation.correlate_purls(&purls)?;
    let statuses = correlation.status_slugs();

    // The recommend endpoint remaps winner PURLs; here we just benchmark
    // the hydrate_recommend_matches path directly.
    let v3_result = trustify_module_correlation::service::hydrate::hydrate_recommend_matches(
        matches, &statuses, &txn,
    )
    .await?;
    let v3_time = start_v3.elapsed();
    let v3_count: usize = v3_result.values().map(|v| v.len()).sum();

    log::info!(
        "v3 recommend: {} entries across {} purls in {}",
        v3_count,
        v3_result.len(),
        humantime::Duration::from(v3_time),
    );

    log::info!(
        "speedup: {:.1}x (v3a={}, v3={})",
        v3a_time.as_secs_f64() / v3_time.as_secs_f64(),
        humantime::Duration::from(v3a_time),
        humantime::Duration::from(v3_time),
    );

    Ok(())
}
