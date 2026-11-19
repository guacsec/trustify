use crate::{
    crypto::model::{
        CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationRequest, PolicyEvaluationResponse,
        RemediationImportResult, RemediationMapping,
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

/// Verifies that JSON remediation mappings can be imported and are stored.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn import_remediations_json(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given: a JSON payload with two remediation mappings
    let app = caller(ctx).await?;
    let payload = serde_json::json!([
        {
            "algorithm_name": "RSA-2048",
            "algorithm_primitive": null,
            "replacement_name": "ML-KEM-768",
            "replacement_standard": "FIPS 203",
            "replacement_primitive": "KEM"
        },
        {
            "algorithm_name": "ECDSA",
            "algorithm_primitive": null,
            "replacement_name": "ML-DSA-65",
            "replacement_standard": "FIPS 204",
            "replacement_primitive": "Signature"
        }
    ]);

    // When: the payload is POSTed to the import endpoint
    let request = TestRequest::post()
        .uri("/api/v3/crypto/remediation/import")
        .set_json(&payload)
        .to_request();
    let response = app.call_service(request).await;

    // Then: the import succeeds and reports 2 processed mappings
    assert_eq!(response.status(), StatusCode::OK);
    let result: RemediationImportResult = actix_web::test::read_body_json(response).await;
    assert_eq!(result.count, 2, "expected 2 imported mappings");

    // Then: the mappings are retrievable via GET /v3/crypto/remediation
    let list_request = TestRequest::get()
        .uri("/api/v3/crypto/remediation")
        .to_request();
    let mappings: Vec<RemediationMapping> = app.call_and_read_body_json(list_request).await;
    assert_eq!(mappings.len(), 2, "expected 2 stored mappings");

    let rsa = mappings
        .iter()
        .find(|m| m.algorithm_name == "RSA-2048")
        .expect("RSA-2048 mapping should be present");
    assert_eq!(rsa.replacement_name, "ML-KEM-768");
    assert_eq!(rsa.replacement_standard.as_deref(), Some("FIPS 203"));

    Ok(())
}

/// Verifies that CSV remediation mappings can be imported and are stored.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn import_remediations_csv(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given: a CSV payload with one remediation mapping
    let app = caller(ctx).await?;
    let csv = b"algorithm_name,algorithm_primitive,replacement_name,replacement_standard,replacement_primitive\nSHA-1,,SLH-DSA-SHA2-128s,FIPS 205,Hash-based\n";

    // When: the CSV is POSTed with text/csv content-type
    let request = TestRequest::post()
        .uri("/api/v3/crypto/remediation/import")
        .insert_header(("content-type", "text/csv"))
        .set_payload(csv.to_vec())
        .to_request();
    let response = app.call_service(request).await;

    // Then: the import succeeds and reports 1 processed mapping
    assert_eq!(response.status(), StatusCode::OK);
    let result: RemediationImportResult = actix_web::test::read_body_json(response).await;
    assert_eq!(result.count, 1, "expected 1 imported mapping");

    // Then: the mapping is stored with correct values
    let list_request = TestRequest::get()
        .uri("/api/v3/crypto/remediation")
        .to_request();
    let mappings: Vec<RemediationMapping> = app.call_and_read_body_json(list_request).await;
    let sha1 = mappings
        .iter()
        .find(|m| m.algorithm_name == "SHA-1")
        .expect("SHA-1 mapping should be present");
    assert_eq!(sha1.replacement_name, "SLH-DSA-SHA2-128s");
    assert_eq!(sha1.replacement_standard.as_deref(), Some("FIPS 205"));

    Ok(())
}

/// Verifies that re-importing the same mappings updates existing entries (idempotent).
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn import_remediations_idempotent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given: a mapping is imported once
    let app = caller(ctx).await?;
    let initial = serde_json::json!([{
        "algorithm_name": "RSA-2048",
        "algorithm_primitive": null,
        "replacement_name": "ML-KEM-768",
        "replacement_standard": "FIPS 203",
        "replacement_primitive": null
    }]);

    let request = TestRequest::post()
        .uri("/api/v3/crypto/remediation/import")
        .set_json(&initial)
        .to_request();
    app.call_service(request).await;

    // When: the same algorithm is re-imported with an updated replacement
    let updated = serde_json::json!([{
        "algorithm_name": "RSA-2048",
        "algorithm_primitive": null,
        "replacement_name": "ML-KEM-1024",
        "replacement_standard": "FIPS 203",
        "replacement_primitive": null
    }]);
    let request = TestRequest::post()
        .uri("/api/v3/crypto/remediation/import")
        .set_json(&updated)
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Then: only one mapping exists and it reflects the update (no duplicate)
    let list_request = TestRequest::get()
        .uri("/api/v3/crypto/remediation")
        .to_request();
    let mappings: Vec<RemediationMapping> = app.call_and_read_body_json(list_request).await;
    let rsa_mappings: Vec<_> = mappings
        .iter()
        .filter(|m| m.algorithm_name == "RSA-2048")
        .collect();
    assert_eq!(
        rsa_mappings.len(),
        1,
        "re-import must not duplicate mappings"
    );
    assert_eq!(
        rsa_mappings[0].replacement_name, "ML-KEM-1024",
        "re-import must update existing mapping"
    );

    Ok(())
}

/// Verifies that algorithm listing includes the recommendation field after import.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_algorithms_includes_recommendation(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given: a CBOM is ingested and a remediation mapping is imported for SHA1
    let app = caller(ctx).await?;
    ingest_cbom(&app).await;

    let remediation = serde_json::json!([{
        "algorithm_name": "SHA1",
        "algorithm_primitive": null,
        "replacement_name": "SLH-DSA-SHA2-128s",
        "replacement_standard": "FIPS 205",
        "replacement_primitive": null
    }]);
    let import_request = TestRequest::post()
        .uri("/api/v3/crypto/remediation/import")
        .set_json(&remediation)
        .to_request();
    app.call_service(import_request).await;

    // When: algorithms are listed (limit=100 to fetch all assets from the CBOM)
    let request = TestRequest::get()
        .uri("/api/v3/crypto/algorithm?total=true&limit=100")
        .to_request();
    let response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    // Then: SHA1 entry has a populated recommendation field
    let sha1 = response
        .items
        .iter()
        .find(|a| a.name == "SHA1")
        .expect("SHA1 algorithm should be in the listing");
    assert_eq!(
        sha1.recommendation.as_deref(),
        Some("SLH-DSA-SHA2-128s (FIPS 205)"),
        "SHA1 recommendation should reflect the imported mapping"
    );

    Ok(())
}

/// Verifies that only packages are counted as generating a crypto asset: a machine-learning model
/// generating the same asset is not a package.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn packages_count_ignores_non_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    use serde_json::{Value, json};

    // Given a CBOM where `crypto-library` (a package) provides AES
    let mut cbom: Value =
        serde_json::from_slice(&document_bytes("cyclonedx/cryptographic/cbom.json").await?)?;

    // And a machine-learning model, which isn't a package, also provides AES
    cbom["components"].as_array_mut().unwrap().push(json!({
        "type": "machine-learning-model",
        "bom-ref": "ml-model",
        "name": "some-model",
        "version": "1.0.0",
        "purl": "pkg:huggingface/acme/some-model@1.0.0",
    }));
    cbom["dependencies"].as_array_mut().unwrap().push(json!({
        "ref": "ml-model",
        "provides": ["aes128gcm"],
    }));
    ctx.ingest_json(cbom).await?;

    let app = caller(ctx).await?;
    let request = TestRequest::get()
        .uri("/api/v3/crypto/algorithm?total=true")
        .to_request();
    let response: PaginatedResults<CryptoAlgorithmSummary> =
        app.call_and_read_body_json(request).await;

    // Then only the package is counted
    let aes = response
        .items
        .iter()
        .find(|item| item.name == "AES")
        .expect("AES should be listed");
    assert_eq!(aes.packages_count, 1, "{aes:#?}");

    Ok(())
}
