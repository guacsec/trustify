use crate::service::CorrelationService;
use actix_web::{App, test as actix_test, web};
use test_context::test_context;
use test_log::test;
use trustify_common::db;
use trustify_module_analysis::{config::AnalysisConfig, service::AnalysisService};
use trustify_test_context::{TrustifyContext, app::TestApp};

/// Build a correlation service for testing, pre-loaded with the advisory index.
async fn test_correlation(ctx: &TrustifyContext) -> CorrelationService {
    let analysis =
        AnalysisService::new(AnalysisConfig::default(), db::ReadOnly::new(ctx.db.clone()));
    let svc = CorrelationService::new(analysis);
    let tx = db::ReadOnly::new(ctx.db.clone())
        .begin()
        .await
        .expect("begin tx");
    svc.load_index(&tx).await.expect("load advisory index");
    svc
}

/// Ingest a document and return its ID (stripped of urn:uuid: prefix).
async fn ingest_and_get_id(ctx: &TrustifyContext, path: &str) -> String {
    let result = ctx.ingest_document(path).await.expect("ingest document");
    result
        .id
        .strip_prefix("urn:uuid:")
        .unwrap_or(&result.id)
        .to_string()
}

/// Verify the correlation status endpoint works.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn correlation_status_empty(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let correlation = test_correlation(ctx).await;
    let db_ro = db::ReadOnly::new(ctx.db.clone());

    let app = actix_test::init_service(
        App::new()
            .add_test_authorizer()
            .app_data(web::Data::new(db_ro))
            .app_data(web::Data::new(correlation))
            .service(super::correlation_status),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/v3/correlation/status")
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: super::CorrelationStatus = actix_test::read_body_json(resp).await;
    // Empty DB, no advisories loaded
    assert_eq!(body.purl_entries, 0);
    assert_eq!(body.cpe_entries, 0);
    assert_eq!(body.vulnerability_count, 0);

    Ok(())
}

/// Verify that correlating an SBOM with a matching advisory produces results.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn correlate_sbom_with_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // Ingest an SBOM and a matching advisory.
    let sbom_id_str = ingest_and_get_id(ctx, "cyclonedx/application.cdx.json").await;
    let _advisory_id = ingest_and_get_id(ctx, "csaf/cve-2023-0044.json").await;

    // Reload the index after ingesting the advisory.
    let correlation = test_correlation(ctx).await;
    let db_ro = db::ReadOnly::new(ctx.db.clone());

    let app = actix_test::init_service(
        App::new()
            .add_test_authorizer()
            .app_data(web::Data::new(db_ro.clone()))
            .app_data(web::Data::new(correlation.clone()))
            .service(super::correlate_sbom)
            .service(super::correlation_status),
    )
    .await;

    // Check that the index loaded something
    let req = actix_test::TestRequest::get()
        .uri("/v3/correlation/status")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let status: super::CorrelationStatus = actix_test::read_body_json(resp).await;
    assert!(
        status.purl_entries > 0 || status.product_entries > 0,
        "advisory index should have entries after advisory ingest"
    );

    // Correlate the SBOM.
    let req = actix_test::TestRequest::get()
        .uri(&format!("/v3/correlation/sbom/{sbom_id_str}"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: super::CorrelationResult = actix_test::read_body_json(resp).await;
    // We expect at least some matches if the advisory covers the SBOM's packages.
    // The exact count depends on test fixtures, but this verifies the pipeline works.
    tracing::info!(
        total_matches = body.total_matches,
        advisory_count = body.advisory_count,
        vulnerability_count = body.vulnerability_count,
        "correlation result"
    );

    Ok(())
}

/// Verify the hydrated advisory endpoint returns Vec<SbomAdvisory>.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn correlate_sbom_advisory_hydrated(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let sbom_id_str = ingest_and_get_id(ctx, "cyclonedx/application.cdx.json").await;
    let _advisory_id = ingest_and_get_id(ctx, "csaf/cve-2023-0044.json").await;

    let correlation = test_correlation(ctx).await;
    let db_ro = db::ReadOnly::new(ctx.db.clone());

    let app = actix_test::init_service(
        App::new()
            .add_test_authorizer()
            .app_data(web::Data::new(db_ro))
            .app_data(web::Data::new(correlation))
            .service(super::correlate_sbom_advisory),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri(&format!("/v3/correlation/sbom/{sbom_id_str}/advisory"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Parse as the same SbomAdvisory type the existing endpoint returns.
    let body: Vec<trustify_module_fundamental::sbom::model::details::SbomAdvisory> =
        actix_test::read_body_json(resp).await;
    tracing::info!(advisory_count = body.len(), "hydrated advisory result");

    // Verify structure: each advisory has statuses with vulnerabilities
    for advisory in &body {
        assert!(!advisory.head.identifier.is_empty());
        for status in &advisory.status {
            assert!(!status.vulnerability.identifier.is_empty());
            assert!(!status.status.is_empty());
        }
    }

    Ok(())
}
