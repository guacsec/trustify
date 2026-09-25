use crate::{
    crypto::model::{
        CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationRequest, PolicyEvaluationResponse,
    },
    crypto::service::policy::PolicyVerdict,
    test::caller,
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};

async fn ingest_cbom(app: &impl CallService) -> IngestResult {
    let request = TestRequest::post()
        .uri("/api/v3/sbom")
        .set_payload(
            document_bytes("cyclonedx/cryptographic/keycloak-cbom.json")
                .await
                .unwrap(),
        )
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    actix_web::test::read_body_json(response).await
}

/// Verifies that listing algorithms returns expected results from a CBOM.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_algorithms(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    let request = TestRequest::get()
        .uri("/api/v3/crypto/algorithm?total=true")
        .to_request();
    let response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    assert!(
        response.total.unwrap_or(0) > 0,
        "expected algorithms from CBOM"
    );

    for algo in &response.items {
        assert!(
            matches!(
                algo.policy_status,
                PolicyVerdict::Compliant | PolicyVerdict::Warning | PolicyVerdict::NonCompliant
            ),
            "algorithm {} should have a valid policy_status",
            algo.name
        );
        assert!(
            algo.sboms_count >= 1,
            "algorithm {} should appear in at least 1 SBOM",
            algo.name
        );
    }

    Ok(())
}

/// Verifies that the asset_type filter limits results to the requested type.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_algorithms_with_asset_type_filter(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    // Given: request filtered to Algorithm type only
    let request = TestRequest::get()
        .uri("/api/v3/crypto/algorithm?total=true&asset_type=algorithm")
        .to_request();
    let algo_response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    // Then: all results are algorithms
    let algo_count = algo_response.total.unwrap_or(0);
    assert!(algo_count > 0, "expected algorithms from CBOM");
    for item in &algo_response.items {
        assert_eq!(
            item.asset_type.to_string(),
            "algorithm",
            "all items should be algorithms"
        );
    }

    // Given: request filtered to RelatedCryptoMaterial type
    let request = TestRequest::get()
        .uri("/api/v3/crypto/algorithm?total=true&asset_type=related-crypto-material")
        .to_request();
    let material_response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    // Then: all results are related-crypto-material and counts differ
    let material_count = material_response.total.unwrap_or(0);
    assert!(
        material_count > 0,
        "expected related-crypto-material from CBOM"
    );
    for item in &material_response.items {
        assert_eq!(
            item.asset_type.to_string(),
            "related-crypto-material",
            "all items should be related-crypto-material"
        );
    }

    // Given: request without filter returns all types
    let request = TestRequest::get()
        .uri("/api/v3/crypto/algorithm?total=true")
        .to_request();
    let all_response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    let all_count = all_response.total.unwrap_or(0);
    assert!(
        all_count >= algo_count + material_count,
        "unfiltered should return at least as many as algorithms + material combined"
    );

    Ok(())
}

/// Verifies that the summary endpoint returns correct aggregate KPI metrics.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_summary(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    let request = TestRequest::get()
        .uri("/api/v3/crypto/summary")
        .to_request();
    let summary: CryptoSummary = app.call_and_read_body_json(request).await;

    // Then: keycloak-cbom has 22 algorithm-type components
    assert_eq!(summary.total_algorithms, 22, "expected 22 algorithms");
    assert!(
        summary.pqc_compliant >= 0,
        "pqc_compliant should be non-negative"
    );
    assert!(
        summary.classical_share_pct >= 0.0 && summary.classical_share_pct <= 100.0,
        "classical_share_pct should be a valid percentage"
    );

    // keycloak-cbom has no PQC algorithms, so all are classical
    assert_eq!(
        summary.pqc_compliant, 0,
        "keycloak-cbom has no PQC-safe algorithms"
    );
    assert!(
        (summary.classical_share_pct - 100.0).abs() < f64::EPSILON,
        "all algorithms should be classical"
    );
    assert_eq!(
        summary.sboms_meeting_pqc, 0,
        "no SBOMs should meet PQC since all algorithms are classical"
    );

    Ok(())
}

/// Verifies that the summary endpoint returns zeros on an empty database.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_summary_empty_db(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let request = TestRequest::get()
        .uri("/api/v3/crypto/summary")
        .to_request();
    let summary: CryptoSummary = app.call_and_read_body_json(request).await;

    assert_eq!(summary.total_algorithms, 0);
    assert_eq!(summary.pqc_compliant, 0);
    assert!((summary.classical_share_pct - 0.0).abs() < f64::EPSILON);
    assert_eq!(summary.sboms_meeting_pqc, 0);

    Ok(())
}

/// Verifies that per-SBOM crypto listing returns assets scoped to that SBOM.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_sbom_crypto(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let ingest = ingest_cbom(&app).await;
    let sbom_id: uuid::Uuid = ingest.id.parse()?;

    let request = TestRequest::get()
        .uri(&format!("/api/v3/sbom/{sbom_id}/crypto?total=true"))
        .to_request();
    let response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    // Then: keycloak-cbom has 56 total crypto components (all types)
    assert_eq!(
        response.total.unwrap_or(0),
        56,
        "expected 56 crypto assets for the SBOM"
    );

    // All results belong to the ingested SBOM
    for item in &response.items {
        assert_eq!(
            item.sbom_id, sbom_id,
            "all results should match the filtered SBOM ID"
        );
    }

    Ok(())
}

/// Verifies that per-SBOM crypto listing supports asset_type filtering.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_sbom_crypto_filtered(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let ingest = ingest_cbom(&app).await;
    let sbom_id: uuid::Uuid = ingest.id.parse()?;

    let request = TestRequest::get()
        .uri(&format!(
            "/api/v3/sbom/{sbom_id}/crypto?total=true&asset_type=algorithm"
        ))
        .to_request();
    let response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    assert_eq!(
        response.total.unwrap_or(0),
        22,
        "expected 22 algorithms for the SBOM"
    );

    for item in &response.items {
        assert_eq!(item.asset_type.to_string(), "algorithm");
        assert_eq!(item.sbom_id, sbom_id);
    }

    Ok(())
}

/// Verifies policy evaluation across all SBOMs.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evaluate_policy(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    let request = TestRequest::post()
        .uri("/api/v3/crypto/policy/evaluate")
        .set_json(PolicyEvaluationRequest { sbom_id: None })
        .to_request();
    let response: PolicyEvaluationResponse = app.call_and_read_body_json(request).await;

    assert!(response.summary.total > 0, "expected algorithms from CBOM");
    assert_eq!(
        response.summary.total,
        response.summary.compliant + response.summary.warning + response.summary.non_compliant,
        "summary counts should add up to total"
    );

    // SHA1 in keycloak-cbom should be NonCompliant
    let sha1 = response.results.iter().find(|r| r.name == "SHA1");
    assert!(sha1.is_some(), "SHA1 should be present in results");
    assert_eq!(sha1.unwrap().verdict, PolicyVerdict::NonCompliant);

    // ECDH should be Warning (classical in transition)
    let ecdh = response.results.iter().find(|r| r.name == "ECDH");
    assert!(ecdh.is_some(), "ECDH should be present in results");
    assert_eq!(ecdh.unwrap().verdict, PolicyVerdict::Warning);

    Ok(())
}

/// Verifies policy evaluation filtered to a specific SBOM.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evaluate_policy_with_sbom_filter(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let ingest = ingest_cbom(&app).await;
    let sbom_id: uuid::Uuid = ingest.id.parse()?;

    let request = TestRequest::post()
        .uri("/api/v3/crypto/policy/evaluate")
        .set_json(PolicyEvaluationRequest {
            sbom_id: Some(sbom_id),
        })
        .to_request();
    let response: PolicyEvaluationResponse = app.call_and_read_body_json(request).await;

    assert!(
        response.summary.total > 0,
        "expected algorithms for the specific SBOM"
    );

    for result in &response.results {
        assert_eq!(
            result.sbom_id, sbom_id,
            "all results should match the filtered SBOM ID"
        );
    }

    Ok(())
}

/// Verifies policy evaluation on an empty database returns zero results.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evaluate_policy_empty_db(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v3/crypto/policy/evaluate")
        .set_json(PolicyEvaluationRequest { sbom_id: None })
        .to_request();
    let response: PolicyEvaluationResponse = app.call_and_read_body_json(request).await;

    assert_eq!(response.summary.total, 0);
    assert!(response.results.is_empty());

    Ok(())
}
