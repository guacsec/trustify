#![recursion_limit = "512"]

#[path = "common.rs"]
mod common;

use actix_http::StatusCode;
use actix_web::{App, HttpMessage, test::TestRequest, web};
use common::caller_with;
use rstest::rstest;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde_json::json;
use test_context::test_context;
use trustify_auth::{
    authenticator::user::{UserDetails, UserInformation},
    authorizer::{Authorizer, AuthorizerConfig},
};
use trustify_common::db;
use trustify_entity::{exploit, weakness};
use trustify_module_ingestor::endpoints::{Config, configure};
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
    document_bytes_raw,
};
use utoipa_actix_web::AppExt;
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
            Default::default(),
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

/// Catalog uploads require their own create permission, whether uploaded or fetched.
#[test_context(TrustifyContext)]
#[rstest]
#[case::cwe("cwecatalog", "create.weakness", "create.exploit")]
#[case::kev("cisakev", "create.exploit", "create.weakness")]
#[test_log::test(actix_web::test)]
async fn catalog_upload_permissions(
    ctx: &TrustifyContext,
    #[case] format: &str,
    #[case] required: &str,
    #[case] unrelated: &str,
    #[values(false, true)] from_url: bool,
) -> anyhow::Result<()> {
    let bytes = if format == "cwecatalog" {
        br#"<Weakness_Catalog xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="http://cwe.mitre.org/data/xsd/cwe_schema_v7.2.xsd">
            <Weaknesses><Weakness ID="999999"><Description>Permission test</Description></Weakness></Weaknesses>
        </Weakness_Catalog>"#.to_vec()
    } else {
        serde_json::to_vec(&json!({
            "catalogVersion": "test", "vulnerabilities": [{"cveID": "CVE-2099-999999"}]
        }))?
    };
    let server = MockServer::start().await;
    Mock::given(path("/catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&server)
        .await;
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(Authorizer::new(Some(
                AuthorizerConfig::default(),
            ))))
            .app_data(web::Data::new(reqwest::Client::new()))
            .into_utoipa_app()
            .configure(|svc| {
                configure(
                    svc,
                    Config::default(),
                    db::ReadWrite::new(ctx.db.clone()),
                    ctx.storage.clone(),
                    None,
                    Vec::new(),
                    Default::default(),
                )
            })
            .into_app(),
    )
    .await;
    for permission in [
        None,
        Some(""),
        Some("create.advisory"),
        Some("create.sbom"),
        Some(unrelated),
        Some(required),
    ] {
        let request = if from_url {
            TestRequest::post()
                .uri("/v3/upload/from-url")
                .set_json(json!({"url": format!("{}/catalog", server.uri())}))
        } else {
            TestRequest::post()
                .uri("/v3/upload")
                .set_payload(bytes.clone())
        }
        .to_request();
        if let Some(permission) = permission {
            request
                .extensions_mut()
                .insert(UserInformation::Authenticated(UserDetails {
                    id: "uploader".into(),
                    permissions: if permission.is_empty() {
                        vec![]
                    } else {
                        vec![permission.into()]
                    },
                }));
        }
        let granted = permission == Some(required);
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(
            response.status(),
            if granted { 201 } else { 403 },
            "{format}, from_url={from_url}, {permission:?}"
        );
        let persisted = if format == "cwecatalog" {
            weakness::Entity::find_by_id("CWE-999999")
                .one(&ctx.db)
                .await?
                .is_some()
        } else {
            exploit::Entity::find()
                .filter(exploit::Column::CveId.eq("CVE-2099-999999"))
                .one(&ctx.db)
                .await?
                .is_some()
        };
        assert_eq!(
            persisted, granted,
            "denied uploads must not change catalog data"
        );
    }
    Ok(())
}
