use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::{Config, configure};
use trustify_test_context::document_bytes;

include!("../../../src/test/common.rs");

/// test to see some error message, instead of plain failure
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_broken_refs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("cyclonedx/broken-refs.json")
        .await
        .expect_err("must fail");

    assert_eq!(result.to_string(), "invalid content: Invalid reference: b");

    Ok(())
}

/// test to see some error message and 400, instead of plain failure
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_broken_refs_api(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v3/sbom")
        .set_payload(document_bytes("cyclonedx/broken-refs.json").await?)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}
