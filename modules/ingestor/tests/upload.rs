#[path = "common.rs"]
mod common;

use actix_http::StatusCode;
use actix_web::{test::TestRequest, web};
use common::caller_with;
use rstest::rstest;
use serde_json::json;
use test_context::test_context;
use trustify_common::db;
use trustify_module_ingestor::endpoints::{Config, configure};
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
    document_bytes_raw,
};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

const ADVISORY: &str = "scenarios/S11_bareaffected_substream_firefox/vex/CVE-2023-6135.json";

/// Compressed uploads are detected by their magic bytes, unless a content type is declared.
///
/// The UI relies on this, uploading files without a content type.
#[test_context(TrustifyContext)]
#[rstest]
#[case::plain("", None, StatusCode::CREATED)]
#[case::xz(".xz", None, StatusCode::CREATED)]
#[case::xz_declared(".xz", Some("application/json+xz"), StatusCode::CREATED)]
#[case::xz_octet_stream(".xz", Some("application/octet-stream"), StatusCode::BAD_REQUEST)]
#[test_log::test(actix_web::test)]
async fn upload_compressed(
    ctx: &TrustifyContext,
    #[case] suffix: &str,
    #[case] content_type: Option<&str>,
    #[case] expected: StatusCode,
) -> anyhow::Result<()> {
    let app = caller_with(
        ctx,
        Config {
            upload_limit: 10 * 1024 * 1024,
            ..Default::default()
        },
    )
    .await?;

    let mut request = TestRequest::post()
        .uri("/api/v3/upload")
        .set_payload(document_bytes_raw(format!("{ADVISORY}{suffix}")).await?);
    if let Some(content_type) = content_type {
        request = request.insert_header(("Content-Type", content_type));
    }

    let response = app.call_service(request.to_request()).await;
    assert_eq!(response.status(), expected);

    Ok(())
}

/// Documents fetched from a URL are decompressed as well, ignoring the served content type.
#[test_context(TrustifyContext)]
#[rstest]
#[case::plain("", "application/json")]
#[case::xz(".xz", "application/x-xz")]
#[case::xz_octet_stream(".xz", "application/octet-stream")]
#[test_log::test(actix_web::test)]
async fn upload_compressed_from_url(
    ctx: &TrustifyContext,
    #[case] suffix: &str,
    #[case] content_type: &str,
) -> anyhow::Result<()> {
    let server = MockServer::start().await;
    Mock::given(path("/advisory"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            document_bytes_raw(format!("{ADVISORY}{suffix}")).await?,
            content_type,
        ))
        .mount(&server)
        .await;

    let app = call::caller(|svc| {
        svc.app_data(web::Data::new(reqwest::Client::new()));
        configure(
            svc,
            Config {
                upload_limit: 10 * 1024 * 1024,
                ..Default::default()
            },
            db::ReadWrite::new(ctx.db.clone()),
            ctx.storage.clone(),
            None,
            Vec::new(),
        )
    })
    .await?;

    let request = TestRequest::post()
        .uri("/api/v3/upload/from-url")
        .set_json(json!({ "url": format!("{}/advisory", server.uri()) }))
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    Ok(())
}

/// The limit applies to the decompressed size.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn upload_compressed_too_large(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller_with(
        ctx,
        Config {
            // the compressed advisory is ~19 KiB, decompressed ~594 KiB
            upload_limit: 100 * 1024,
            ..Default::default()
        },
    )
    .await?;

    let request = TestRequest::post()
        .uri("/api/v3/upload")
        .set_payload(document_bytes_raw(format!("{ADVISORY}.xz")).await?)
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}
