include!("../src/test/common.rs");

use actix_http::StatusCode;
use actix_web::http;
use actix_web::test::TestRequest;
use sea_orm::{EntityTrait, PaginatorTrait};
use test_context::test_context;
use test_log::test;
use trustify_entity::sbom;
use trustify_module_fundamental::{Config, configure};
use trustify_test_context::document_bytes_raw;

async fn assert(
    ctx: &TrustifyContext,
    name: &str,
    content_type: impl Into<Option<&str>>,
    code: StatusCode,
) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let request = TestRequest::post().uri("/api/v3/sbom");

    let request = match content_type.into() {
        Some(ct) => request.append_header((http::header::CONTENT_TYPE, ct)),
        None => request,
    };

    let request = request
        .set_payload(document_bytes_raw(name).await?)
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), code);

    Ok(())
}

/// Ensure that when not indicating a content type, we just auto-detect it.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_compressed(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert(
        ctx,
        "cyclonedx/decompress/simple.json",
        None,
        StatusCode::CREATED,
    )
    .await?;
    assert(
        ctx,
        "cyclonedx/decompress/simple.json.bz2",
        None,
        StatusCode::CREATED,
    )
    .await?;
    assert(
        ctx,
        "cyclonedx/decompress/simple.json.gz",
        None,
        StatusCode::CREATED,
    )
    .await?;
    assert(
        ctx,
        "cyclonedx/decompress/simple.json.xz",
        None,
        StatusCode::CREATED,
    )
    .await?;

    // must only be one, as all are the same

    assert_eq!(sbom::Entity::find().count(&ctx.db).await?, 1);

    Ok(())
}

/// Ensure that when we provide a content type, we really expect it.
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_wrong_content_type(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert(
        ctx,
        "cyclonedx/decompress/simple.json",
        "application/json+bzip2",
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert(
        ctx,
        "cyclonedx/decompress/simple.json.bz2",
        "application/json+bzip2",
        StatusCode::CREATED,
    )
    .await?;
    assert(
        ctx,
        "cyclonedx/decompress/simple.json.gz",
        "application/json+bzip2",
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert(
        ctx,
        "cyclonedx/decompress/simple.json.xz",
        "application/json+bzip2",
        StatusCode::BAD_REQUEST,
    )
    .await?;

    // must only be one, as all are the same, and actually only one succeeded

    assert_eq!(sbom::Entity::find().count(&ctx.db).await?, 1);

    Ok(())
}
