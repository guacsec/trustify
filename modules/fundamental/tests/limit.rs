use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::{Config, configure};
use trustify_test_context::document_bytes_raw;

include!("../src/test/common.rs");

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_bomb_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller_with(
        ctx,
        Config {
            sbom_upload_limit: 1024 * 1024,
            advisory_upload_limit: 1024 * 1024,
            max_group_name_length: 32,
        },
    )
    .await?;

    let request = TestRequest::post()
        .uri("/api/v2/sbom")
        .set_payload(document_bytes_raw("bomb.bz2").await?)
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_bomb_advisory(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller_with(
        ctx,
        Config {
            sbom_upload_limit: 1024 * 1024,
            advisory_upload_limit: 1024 * 1024,
            max_group_name_length: 32,
        },
    )
    .await?;

    let request = TestRequest::post()
        .uri("/api/v2/advisory")
        .set_payload(document_bytes_raw("bomb.bz2").await?)
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}
