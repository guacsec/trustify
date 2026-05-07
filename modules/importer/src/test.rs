#![cfg(test)]

use super::model::{
    CommonImporter, Importer, ImporterConfiguration, ImporterData, SbomImporter, State,
};
use actix_http::{Request, body::BoxBody};
use actix_web::{
    App,
    dev::{Service, ServiceResponse},
    http::{StatusCode, header},
    test as actix,
};
use serde_json::json;
use std::time::Duration;
use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_test_context::{ReadOnly, TrustifyContext, app::TestApp};
use utoipa_actix_web::AppExt;

fn mock_configuration(source: impl Into<String>) -> ImporterConfiguration {
    ImporterConfiguration::Sbom(SbomImporter {
        common: CommonImporter {
            disabled: false,
            period: Duration::from_secs(30),
            description: None,
            labels: Default::default(),
        },
        source: source.into(),
        keys: vec![],

        only_patterns: vec![],
        v3_signatures: false,

        size_limit: None,
        fetch_retries: None,
        ignore_missing: false,
    })
}

fn mock_importer(result: &Importer, source: impl Into<String>) -> Importer {
    Importer {
        name: "foo".into(),
        heartbeat: None,
        data: ImporterData {
            configuration: mock_configuration(source),
            state: State::Waiting,
            last_change: result.data.last_change, // we can't predict timestamps
            last_success: None,
            last_error: None,
            last_run: None,
            progress: Default::default(),
            continuation: serde_json::Value::Null,
        },
    }
}

async fn app(
    ctx: &TrustifyContext,
) -> impl Service<Request, Response = ServiceResponse<BoxBody>, Error = actix_web::Error> {
    let db = ctx.db.clone();
    actix::init_service(
        App::new()
            .into_utoipa_app()
            .add_test_authorizer()
            .service(
                utoipa_actix_web::scope("/api").configure(|svc| {
                    super::endpoints::configure(svc, db, PaginationCache::for_test())
                }),
            )
            .into_app(),
    )
    .await
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn default(ctx: TrustifyContext) {
    let app = app(&ctx).await;

    // create one

    let req = actix::TestRequest::post()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("bar"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // now list all

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Vec<Importer> = actix::read_body_json(resp).await;
    assert_eq!(
        result,
        vec![Importer {
            name: "foo".into(),
            heartbeat: None,
            data: ImporterData {
                configuration: mock_configuration("bar"),
                state: State::Waiting,
                last_change: result[0].data.last_change, // we can't predict timestamps
                last_success: None,
                last_run: None,
                last_error: None,
                progress: Default::default(),
                continuation: serde_json::Value::Null,
            }
        }]
    );

    // update it

    let req = actix::TestRequest::put()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("baz"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "baz"));

    // delete it

    let req = actix::TestRequest::delete()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get none

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn oplock(ctx: TrustifyContext) {
    let app = app(&ctx).await;

    // create one

    let req = actix::TestRequest::post()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("bar"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // update it (no lock)

    let req = actix::TestRequest::put()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("baz"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let etag = resp.headers().get(header::ETAG);
    assert!(etag.is_some());
    let etag = etag.cloned().unwrap();

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "baz"));

    // update it (with lock)

    let req = actix::TestRequest::put()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("buz"))
        .append_header((header::IF_MATCH, etag.clone()))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "buz"));

    // update it (with broken lock)

    let req = actix::TestRequest::put()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("boz"))
        .append_header((header::IF_MATCH, etag.clone()))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);

    // update it (with wrong name)

    let req = actix::TestRequest::put()
        .uri("/api/v3/importer/foo2")
        .set_json(mock_configuration("boz"))
        .append_header((header::IF_MATCH, etag.clone()))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // get it (must not change)

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let old_etag = etag;
    let etag = resp.headers().get(header::ETAG);
    assert!(etag.is_some());
    let etag = etag.cloned().unwrap();
    assert_ne!(old_etag, etag);

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "buz"));

    // delete it (wrong lock)

    let req = actix::TestRequest::delete()
        .uri("/api/v3/importer/foo")
        .append_header((header::IF_MATCH, old_etag.clone()))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it (must still be there)

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "buz"));

    // delete it (correct lock)

    let req = actix::TestRequest::delete()
        .uri("/api/v3/importer/foo")
        .append_header((header::IF_MATCH, etag.clone()))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get none

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn patch(ctx: TrustifyContext) {
    let app = app(&ctx).await;

    // create one

    let req = actix::TestRequest::post()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("bar"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // get it

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "bar"));

    // patch it

    let req = actix::TestRequest::patch()
        .uri("/api/v3/importer/foo")
        .set_json(json!({
            "sbom": {
                "source": "baz",
            },
        }))
        .insert_header(("content-type", "application/merge-patch+json"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it (again)

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Importer = actix::read_body_json(resp).await;
    assert_eq!(result, mock_importer(&result, "baz"));

    // delete it

    let req = actix::TestRequest::delete()
        .uri("/api/v3/importer/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // try again

    let req = actix::TestRequest::patch()
        .uri("/api/v3/importer/foo")
        .set_json(json!({
            "sbom": {
                "source": "bar",
            },
        }))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test_context(ReadOnly<TrustifyContext>)]
#[test(actix_web::test)]
async fn read_only(ctx: &mut ReadOnly<TrustifyContext>) {
    let app = app(ctx).await;

    // list all

    let req = actix::TestRequest::get()
        .uri("/api/v3/importer")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Vec<Importer> = actix::read_body_json(resp).await;
    assert_eq!(result, vec![]);

    // try to create one, must fail

    let req = actix::TestRequest::post()
        .uri("/api/v3/importer/foo")
        .set_json(mock_configuration("bar"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
