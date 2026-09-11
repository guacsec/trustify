use crate::{
    crypto::model::{CryptoAlgorithmSummary, PolicyEvaluationRequest, PolicyEvaluationResponse},
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

    // Every algorithm should have a policy_status field
    for algo in &response.items {
        assert!(
            matches!(
                algo.policy_status,
                PolicyVerdict::Compliant | PolicyVerdict::Warning | PolicyVerdict::NonCompliant
            ),
            "algorithm {} should have a valid policy_status",
            algo.name
        );
    }

    Ok(())
}

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

    // All results should belong to the specified SBOM
    for result in &response.results {
        assert_eq!(
            result.sbom_id, sbom_id,
            "all results should match the filtered SBOM ID"
        );
    }

    Ok(())
}

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
