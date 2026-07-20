#![recursion_limit = "512"]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use std::collections::HashSet;
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

/// Verify SBOM advisory correlation matches the SQL-based result exactly.
///
/// The quarkus-bom SBOM should produce 22 advisories from both the SQL and
/// in-memory paths, because SBOM correlation uses both purl_status and
/// product_status matching.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn sbom_advisory_count_matches_sql(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let sbom = &result.files["spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2"];
    let sbom_id = Id::parse_uuid(&sbom.id)?;

    // SQL baseline
    let sbom_service = SbomService::new(PaginationCache::for_test());
    let v3a = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");

    // In-memory correlation
    let correlation = create_correlation(&ctx).await?;
    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };
    let matches = correlation.correlate_sbom(sbom_uuid)?;
    let statuses = correlation.status_slugs();
    let txn = ctx.db.begin().await?;
    let v3 =
        trustify_module_correlation::service::hydrate::hydrate_matches(matches, &statuses, &txn)
            .await?;

    assert_eq!(
        v3a.advisories.len(),
        v3.len(),
        "SBOM advisory count must match: SQL={}, correlation={}",
        v3a.advisories.len(),
        v3.len(),
    );
    assert_eq!(v3.len(), 22, "quarkus-bom should have 22 advisories");

    Ok(())
}

/// Verify vulnerability details match between SQL and in-memory paths.
///
/// CVE-2023-4853 should produce the same advisory count from both paths.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn vulnerability_advisory_count_matches_sql(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let vuln_id = "CVE-2023-4853";

    // SQL baseline
    let vuln_service = VulnerabilityService::new(PaginationCache::for_test());
    let v3a = vuln_service
        .fetch_vulnerability(vuln_id, Deprecation::Ignore, true, &ctx.db)
        .await?
        .expect("vulnerability should exist");

    // In-memory correlation
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;

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

    let v3 = trustify_module_correlation::service::hydrate::hydrate_vulnerability_advisories(
        &vuln,
        &advisory_vulns,
        &vuln_scores,
        matches,
        &vuln_entries,
        &statuses,
        &txn,
    )
    .await?;

    assert_eq!(
        v3a.advisories.len(),
        v3.len(),
        "vulnerability advisory count must match: SQL={}, correlation={}",
        v3a.advisories.len(),
        v3.len(),
    );

    Ok(())
}

/// Verify PURL advisory results: in-memory path returns purl_status matches only.
///
/// The SQL path (`PurlService::purl_by_purl`) queries both `purl_status` and
/// `product_status` tables. The in-memory `correlate_purls` currently only
/// queries `AdvisoryIndex.by_purl` (sourced from `purl_status`), so it may
/// return fewer advisories when product_status entries exist for the package.
///
/// This test verifies:
/// 1. Both paths return non-empty results
/// 2. Every advisory found by correlation is also found by SQL
/// 3. The SQL path may find additional advisories from product_status matches
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn purl_advisories_subset_of_sql(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purl_str = "pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar";
    let purl = Purl::try_from(purl_str)?;

    // SQL baseline — includes both purl_status and product_status matches
    let purl_service = PurlService::new(PaginationCache::for_test());
    let v3a = purl_service
        .purl_by_purl(&purl, Deprecation::Ignore, &ctx.db)
        .await?
        .expect("PURL should exist");

    // In-memory correlation — purl_status matches only
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;
    let matches = correlation.correlate_purls(&[purl])?;
    let statuses = correlation.status_slugs();
    let purl_matches = matches.into_values().next().unwrap_or_default();
    let v3 = trustify_module_correlation::service::hydrate::hydrate_purl_advisories(
        purl_matches,
        &statuses,
        &txn,
    )
    .await?;

    // Both paths should find advisories
    assert!(
        !v3a.advisories.is_empty(),
        "SQL path should find advisories"
    );
    assert!(!v3.is_empty(), "correlation path should find advisories");

    // Correlation results must be a subset of SQL results
    let v3a_vuln_ids: HashSet<_> = v3a
        .advisories
        .iter()
        .flat_map(|a| a.status.iter().map(|s| s.vulnerability.identifier.clone()))
        .collect();
    let v3_vuln_ids: HashSet<_> = v3
        .iter()
        .flat_map(|a| a.status.iter().map(|s| s.vulnerability.identifier.clone()))
        .collect();

    let extra_in_v3: Vec<_> = v3_vuln_ids.difference(&v3a_vuln_ids).collect();
    assert!(
        extra_in_v3.is_empty(),
        "correlation found vulnerabilities not in SQL: {:?}",
        extra_in_v3,
    );

    // SQL may find more due to product_status matches
    let extra_in_sql: Vec<_> = v3a_vuln_ids.difference(&v3_vuln_ids).collect();
    if !extra_in_sql.is_empty() {
        log::info!(
            "SQL found {} additional vulnerabilities from product_status: {:?}",
            extra_in_sql.len(),
            extra_in_sql,
        );
    }

    log::info!(
        "purl advisories: SQL={}, correlation={} (shared vulns={})",
        v3a.advisories.len(),
        v3.len(),
        v3_vuln_ids.intersection(&v3a_vuln_ids).count(),
    );

    Ok(())
}

/// Verify analyze results: correlation returns entries for all input PURLs.
///
/// The SQL `analyze_purls_v3` only returns PURLs that have vulnerability
/// matches. The in-memory `hydrate_analysis` returns entries for all input
/// PURLs (with empty details when no matches are found). Both should find
/// the same set of vulnerabilities for PURLs that have matches.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn analyze_vulnerability_ids_match_sql(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purls = [
        "pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?type=jar",
        "pkg:maven/io.netty/netty-handler@4.1.86.Final-redhat-00001?type=jar",
        "pkg:maven/org.apache.james/apache-mime4j-core@0.8.9-redhat-00001?type=jar",
    ];

    // SQL baseline
    let vuln_service = VulnerabilityService::new(PaginationCache::for_test());
    let v3a = vuln_service
        .analyze_purls_v3(purls.iter().copied(), &ctx.db)
        .await?;

    // In-memory correlation
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;
    let parsed: Vec<_> = purls
        .iter()
        .filter_map(|p| Purl::try_from(*p).ok())
        .collect();
    let matches = correlation.correlate_purls(&parsed)?;
    let statuses = correlation.status_slugs();
    let v3 =
        trustify_module_correlation::service::hydrate::hydrate_analysis(matches, &statuses, &txn)
            .await?;

    // Collect all vulnerability IDs from both responses
    let v3a_vuln_ids: HashSet<_> = v3a
        .0
        .values()
        .flat_map(|r| r.details.iter().map(|d| d.head.identifier.clone()))
        .collect();
    let v3_vuln_ids: HashSet<_> =
        v3.0.values()
            .flat_map(|r| r.details.iter().map(|d| d.head.identifier.clone()))
            .collect();

    // Correlation vulnerability IDs should be a subset of SQL results
    // (SQL includes product_status matches that correlation doesn't have)
    let extra_in_v3: Vec<_> = v3_vuln_ids.difference(&v3a_vuln_ids).collect();
    assert!(
        extra_in_v3.is_empty(),
        "correlation found vulnerabilities not in SQL: {:?}",
        extra_in_v3,
    );

    // Log what SQL found additionally from product_status
    let extra_in_sql: Vec<_> = v3a_vuln_ids.difference(&v3_vuln_ids).collect();
    if !extra_in_sql.is_empty() {
        log::info!(
            "SQL found {} additional vulnerabilities from product_status: {:?}",
            extra_in_sql.len(),
            extra_in_sql,
        );
    }

    log::info!(
        "analyze: SQL purls={} details={}, correlation purls={} details={}, shared vulns={}",
        v3a.0.len(),
        v3a.0.values().map(|r| r.details.len()).sum::<usize>(),
        v3.0.len(),
        v3.0.values().map(|r| r.details.len()).sum::<usize>(),
        v3_vuln_ids.intersection(&v3a_vuln_ids).count(),
    );

    Ok(())
}

/// Verify recommend results are non-empty for a known Red Hat patched PURL.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn recommend_returns_results(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purl_strs = ["pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?type=jar"];
    let purls: Vec<_> = purl_strs
        .iter()
        .filter_map(|p| Purl::try_from(*p).ok())
        .collect();

    // SQL baseline
    let purl_service = PurlService::new(PaginationCache::for_test());
    let v3a = purl_service.recommend_purls(&purls, &ctx.db).await?;
    let v3a_count: usize = v3a.values().map(|v| v.len()).sum();

    // In-memory correlation
    let correlation = create_correlation(&ctx).await?;
    let txn = ctx.db.begin().await?;
    let matches = correlation.correlate_purls(&purls)?;
    let statuses = correlation.status_slugs();
    let v3 = trustify_module_correlation::service::hydrate::hydrate_recommend_matches(
        matches, &statuses, &txn,
    )
    .await?;
    let v3_count: usize = v3.values().map(|v| v.len()).sum();

    // Both should return at least one recommendation
    assert!(v3a_count > 0, "SQL recommend should return entries");
    assert!(v3_count > 0, "correlation recommend should return entries");

    log::info!(
        "recommend: SQL={} entries, correlation={} entries",
        v3a_count,
        v3_count,
    );

    Ok(())
}

/// Verify SBOM ubi8 correlation finds 1 advisory matching the SQL result.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn sbom_ubi8_advisory_count_matches_sql(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let sbom = &result.files["spdx/ubi8-8.8-1067.json.bz2"];
    let sbom_id = Id::parse_uuid(&sbom.id)?;

    // SQL baseline
    let sbom_service = SbomService::new(PaginationCache::for_test());
    let v3a = sbom_service
        .fetch_sbom_details(sbom_id.clone(), vec![], &ctx.db)
        .await?
        .expect("SBOM should exist");

    // In-memory correlation
    let correlation = create_correlation(&ctx).await?;
    let sbom_uuid = match sbom_id {
        Id::Uuid(u) => u,
        _ => panic!("expected UUID"),
    };
    let matches = correlation.correlate_sbom(sbom_uuid)?;
    let statuses = correlation.status_slugs();
    let txn = ctx.db.begin().await?;
    let v3 =
        trustify_module_correlation::service::hydrate::hydrate_matches(matches, &statuses, &txn)
            .await?;

    assert_eq!(
        v3a.advisories.len(),
        v3.len(),
        "ubi8 advisory count must match: SQL={}, correlation={}",
        v3a.advisories.len(),
        v3.len(),
    );
    assert_eq!(v3.len(), 1, "ubi8 should have 1 advisory");

    Ok(())
}
