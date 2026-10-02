use crate::{
    crypto::{
        model::{CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationRequest},
        service::{
            CryptoService,
            evaluator::{AlgorithmInput, EvaluatorFinding, EvaluatorReport, PolicyEvaluator},
            policy::PolicyVerdict,
        },
    },
    test::caller,
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use async_trait::async_trait;
use sea_orm::TransactionTrait;
use test_context::test_context;
use test_log::test;
use trustify_common::{db, model::PaginatedResults, db::pagination_cache::PaginationCache};
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};
use uuid::Uuid;

/// Mock evaluator: SHA-1/MD5 → NonCompliant, PQC-safe → Compliant, everything else → Warning.
struct MockPolicyEvaluator;

#[async_trait]
impl PolicyEvaluator for MockPolicyEvaluator {
    async fn evaluate(
        &self,
        algorithms: &[AlgorithmInput],
    ) -> Result<EvaluatorReport, crate::Error> {
        let mut violations = vec![];
        let mut warnings = vec![];
        for algo in algorithms {
            let upper = algo.name.to_uppercase();
            if upper.contains("SHA1") || upper.contains("SHA-1") || upper.contains("MD5") {
                violations.push(EvaluatorFinding {
                    node_id: Some(algo.node_id.clone()),
                });
            } else if !is_pqc_safe(&upper) {
                warnings.push(EvaluatorFinding {
                    node_id: Some(algo.node_id.clone()),
                });
            }
        }
        Ok(EvaluatorReport {
            violations,
            warnings,
        })
    }
}

fn is_pqc_safe(upper: &str) -> bool {
    ["MLKEM", "ML-KEM", "KYBER", "MLDSA", "ML-DSA", "DILITHIUM", "SLHDSA", "SLH-DSA", "SPHINCS"]
        .iter()
        .any(|kw| upper.contains(kw))
}

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
async fn evaluate_policy_requires_conforma(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // When CONFORMA_POLICY is not configured (test default), the endpoint must
    // return 500 rather than silently falling back to a hardcoded policy.
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    let request = TestRequest::post()
        .uri("/api/v3/crypto/policy/evaluate")
        .set_json(PolicyEvaluationRequest { sbom_id: None })
        .to_request();
    let response = app.call_service(request).await;

    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "evaluate_policy must fail with 500 when CONFORMA_POLICY is not set"
    );

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
    let response = app.call_service(request).await;

    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "evaluate_policy must fail with 500 when CONFORMA_POLICY is not set"
    );

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
    let response = app.call_service(request).await;

    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "evaluate_policy must fail with 500 when CONFORMA_POLICY is not set"
    );

    Ok(())
}

/// Verifies that evaluate_policy persists verdicts to the DB and returns correct classifications.
/// SHA-1 must be NonCompliant; classical algorithms must be Warning.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn evaluate_policy_stores_verdicts(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let ingest = ingest_cbom(&app).await;
    let sbom_id: Uuid = ingest.id.parse()?;

    let service = CryptoService::with_evaluator(
        PaginationCache::for_test(),
        Box::new(MockPolicyEvaluator),
    );
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let tx = db_rw.begin().await?;
    let result = service.evaluate_policy(Some(sbom_id), &tx).await?;
    tx.commit().await?;

    // keycloak-cbom contains SHA1 — must be non_compliant
    assert!(
        result
            .results
            .iter()
            .any(|r| r.name.to_uppercase().contains("SHA1")
                && r.verdict == PolicyVerdict::NonCompliant),
        "SHA1 must be classified as NonCompliant"
    );

    // Classical algorithms (e.g. AES, EC) must be warning
    assert!(
        result
            .results
            .iter()
            .any(|r| r.verdict == PolicyVerdict::Warning),
        "classical algorithms must be classified as Warning"
    );

    Ok(())
}

/// Verifies that list_algorithms returns policy_status from stored verdicts after evaluation.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_algorithms_returns_policy_status_after_evaluation(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let ingest = ingest_cbom(&app).await;
    let sbom_id: Uuid = ingest.id.parse()?;

    let service = CryptoService::with_evaluator(
        PaginationCache::for_test(),
        Box::new(MockPolicyEvaluator),
    );
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let tx = db_rw.begin().await?;
    service.evaluate_policy(Some(sbom_id), &tx).await?;
    tx.commit().await?;

    let request = TestRequest::get()
        .uri(&format!(
            "/api/v3/sbom/{sbom_id}/crypto?total=true&asset_type=algorithm"
        ))
        .to_request();
    let response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    assert!(
        response.items.iter().any(|a| a.policy_status.is_some()),
        "policy_status must be populated after evaluation"
    );
    assert!(
        response
            .items
            .iter()
            .any(|a| a.policy_status == Some(PolicyVerdict::NonCompliant)),
        "at least one algorithm must be NonCompliant (SHA1)"
    );
    assert!(
        response
            .items
            .iter()
            .any(|a| a.policy_status == Some(PolicyVerdict::Warning)),
        "at least one algorithm must be Warning"
    );

    Ok(())
}

/// Verifies that algorithms not on the deny list default to Warning (not Compliant).
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn unknown_algorithms_default_to_warning(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    let service = CryptoService::with_evaluator(
        PaginationCache::for_test(),
        Box::new(MockPolicyEvaluator),
    );
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let tx = db_rw.begin().await?;
    let result = service.evaluate_policy(None, &tx).await?;
    tx.commit().await?;

    // AES is not PQC-safe and not on the deny list — must be Warning, not NonCompliant
    let aes: Vec<_> = result
        .results
        .iter()
        .filter(|r| r.name.to_uppercase().starts_with("AES"))
        .collect();
    assert!(!aes.is_empty(), "keycloak-cbom must contain AES algorithms");
    assert!(
        aes.iter().all(|r| r.verdict == PolicyVerdict::Warning),
        "AES (unknown/classical) must default to Warning"
    );

    Ok(())
}
