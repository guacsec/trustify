use crate::{
    crypto::model::{
        CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationRequest, PolicyEvaluationResponse,
        RemediationMapping,
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

/// Verifies that a fresh database lists exactly the bundled mappings without any upload.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_preloaded_remediations(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given a migrated database with its bundled reference data.
    let app = caller(ctx).await?;
    let mut expected: Vec<serde_json::Value> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migration/src/m0002740_preload_nist_crypto_remediation/",
        "NIST-Only-PQC-Remediation-2026-11.display.json"
    )))?;

    // When the read-only listing endpoint is called.
    let request = TestRequest::get()
        .uri("/api/v3/crypto/remediation")
        .to_request();
    let mappings: Vec<RemediationMapping> = app.call_and_read_body_json(request).await;
    let mut actual = mappings
        .into_iter()
        .map(|mapping| {
            assert!(!mapping.id.is_nil());
            let mut value = serde_json::to_value(mapping).unwrap();
            value.as_object_mut().unwrap().remove("id");
            value
        })
        .collect::<Vec<_>>();

    // Then every persisted five-field mapping matches the source, with no foreign rows.
    // Sort by mapping identity, independently of JSON object member order.
    let mapping_key = |mapping: &serde_json::Value| {
        (
            mapping["algorithm_name"].as_str().unwrap().to_owned(),
            mapping["algorithm_primitive"].as_str().map(str::to_owned),
        )
    };
    actual.sort_by_cached_key(mapping_key);
    expected.sort_by_cached_key(mapping_key);
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 32);
    Ok(())
}

/// Verifies that the removed remediation upload route returns 404.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn remediation_upload_route_is_absent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Given a fully configured API.
    let app = caller(ctx).await?;

    // When the removed route receives a POST request.
    let request = TestRequest::post()
        .uri("/api/v3/crypto/remediation/import")
        .to_request();
    let response = app.call_service(request).await;

    // Then no handler is registered for that route.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Verifies that persisted recommendations reach both algorithm listings without an upload.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_algorithms_includes_preloaded_recommendation(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    // Given a CBOM and the mappings preloaded by database migration.
    let app = caller(ctx).await?;
    let ingest = ingest_cbom(&app).await;
    let sbom_id: uuid::Uuid = ingest.id.parse()?;

    // When both the global and per-SBOM inventories are read.
    for uri in [
        "/api/v3/crypto/algorithm?total=true&limit=100".to_owned(),
        format!("/api/v3/sbom/{sbom_id}/crypto?total=true&limit=100"),
    ] {
        let request = TestRequest::get().uri(&uri).to_request();
        let response: PaginatedResults<CryptoAlgorithmSummary> =
            app.call_and_read_body_json(request).await;

        // Then the null-primitive fallback supplies ECDH's recommendation unchanged.
        let ecdh = response.items.iter().find(|a| a.name == "ECDH").unwrap();
        assert_eq!(ecdh.primitive.as_deref(), Some("key-agree"));
        assert_eq!(
            ecdh.recommendation.as_deref(),
            Some(
                "ML-KEM-768 (NIST default); confirm the application-required security strength (FIPS 203)"
            )
        );

        // And algorithms outside the selected dataset do not receive invented mappings.
        let sha1 = response.items.iter().find(|a| a.name == "SHA1").unwrap();
        assert_eq!(sha1.recommendation, None);
    }
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
