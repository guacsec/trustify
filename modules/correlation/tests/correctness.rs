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

/// Verify PURL advisory results match between SQL and in-memory paths.
///
/// The SQL path (`PurlService::purl_by_purl`) queries both `purl_status` and
/// `product_status` tables. The in-memory correlation must produce the same
/// vulnerability set.
#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn purl_advisory_count_matches_sql(ctx: TrustifyContext) -> anyhow::Result<()> {
    let result = ctx.ingest_dataset(Dataset::DS3).await?;
    assert!(result.warnings.is_empty());

    let purl_str = "pkg:maven/io.quarkus/quarkus-vertx-http@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar";
    let purl = Purl::try_from(purl_str)?;

    // SQL baseline
    let purl_service = PurlService::new(PaginationCache::for_test());
    let v3a = purl_service
        .purl_by_purl(&purl, Deprecation::Ignore, &ctx.db)
        .await?
        .expect("PURL should exist");

    // In-memory correlation
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

    let v3a_vuln_ids: HashSet<_> = v3a
        .advisories
        .iter()
        .flat_map(|a| a.status.iter().map(|s| s.vulnerability.identifier.clone()))
        .collect();
    let v3_vuln_ids: HashSet<_> = v3
        .iter()
        .flat_map(|a| a.status.iter().map(|s| s.vulnerability.identifier.clone()))
        .collect();

    assert_eq!(
        v3a_vuln_ids, v3_vuln_ids,
        "vulnerability IDs must match: SQL={:?}, correlation={:?}",
        v3a_vuln_ids, v3_vuln_ids,
    );

    assert_eq!(
        v3a.advisories.len(),
        v3.len(),
        "advisory count must match: SQL={}, correlation={}",
        v3a.advisories.len(),
        v3.len(),
    );

    Ok(())
}

/// Verify analyze results match between SQL and in-memory paths.
///
/// Both paths must find the same set of vulnerabilities for the given PURLs.
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

    let v3a_vuln_ids: HashSet<_> = v3a
        .0
        .values()
        .flat_map(|r| r.details.iter().map(|d| d.head.identifier.clone()))
        .collect();
    let v3_vuln_ids: HashSet<_> =
        v3.0.values()
            .flat_map(|r| r.details.iter().map(|d| d.head.identifier.clone()))
            .collect();

    assert_eq!(
        v3a_vuln_ids, v3_vuln_ids,
        "vulnerability IDs must match: SQL={:?}, correlation={:?}",
        v3a_vuln_ids, v3_vuln_ids,
    );

    let v3a_detail_count: usize = v3a.0.values().map(|r| r.details.len()).sum();
    let v3_detail_count: usize = v3.0.values().map(|r| r.details.len()).sum();
    assert_eq!(
        v3a_detail_count, v3_detail_count,
        "detail count must match: SQL={}, correlation={}",
        v3a_detail_count, v3_detail_count,
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
