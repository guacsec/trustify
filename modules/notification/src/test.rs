#![cfg(test)]

use actix_web::{App, HttpRequest, HttpResponse, http::StatusCode, test as actix, web};
use std::time::Duration;
use test_context::test_context;
use test_log::test;
use trustify_auth::{
    authenticator::user::UserDetails,
    authorizer::{Authorizer, AuthorizerConfig},
};
use trustify_common::db;
use trustify_common::db::change::{
    ChangeBroadcaster, ChangeEntity, ChangeEntry, ChangeOperation, record_change,
};
use trustify_test_context::TrustifyContext;
use trustify_test_context::auth::TestAuthentication;
use utoipa_actix_web::AppExt;
use uuid::Uuid;

// -- Group A: extract_token -------------------------------------------------

#[test]
fn extract_token_basic() {
    assert_eq!(
        crate::inject_token::extract_token("token=abc123").as_deref(),
        Some("abc123")
    );
}

#[test]
fn extract_token_with_other_params() {
    assert_eq!(
        crate::inject_token::extract_token("after=xxx&token=jwt.val&foo=bar").as_deref(),
        Some("jwt.val")
    );
}

#[test]
fn extract_token_missing() {
    assert_eq!(
        crate::inject_token::extract_token("after=xxx&foo=bar"),
        None
    );
}

#[test]
fn extract_token_empty() {
    assert_eq!(crate::inject_token::extract_token(""), None);
}

#[test]
fn extract_token_percent_encoded() {
    assert_eq!(
        crate::inject_token::extract_token("token=abc%20def").as_deref(),
        Some("abc def")
    );
}

#[test]
fn extract_token_no_value() {
    assert_eq!(crate::inject_token::extract_token("token"), None);
}

#[test]
fn extract_token_empty_value() {
    assert_eq!(crate::inject_token::extract_token("token=&foo=bar"), None);
}

// -- Group B: is_allowed ----------------------------------------------------

fn dummy_entry(r#type: ChangeEntity) -> ChangeEntry {
    ChangeEntry {
        cursor: Uuid::now_v7(),
        r#type,
        id: Some(Uuid::now_v7()),
        operation: ChangeOperation::Added,
    }
}

#[test]
fn is_allowed_sbom_with_perm() {
    assert!(crate::endpoints::is_allowed(
        &dummy_entry(ChangeEntity::Sbom),
        true,
        false
    ));
}

#[test]
fn is_allowed_sbom_without_perm() {
    assert!(!crate::endpoints::is_allowed(
        &dummy_entry(ChangeEntity::Sbom),
        false,
        true
    ));
}

#[test]
fn is_allowed_advisory_with_perm() {
    assert!(crate::endpoints::is_allowed(
        &dummy_entry(ChangeEntity::Advisory),
        false,
        true
    ));
}

#[test]
fn is_allowed_advisory_without_perm() {
    assert!(!crate::endpoints::is_allowed(
        &dummy_entry(ChangeEntity::Advisory),
        true,
        false
    ));
}

#[test]
fn is_allowed_no_perms() {
    assert!(!crate::endpoints::is_allowed(
        &dummy_entry(ChangeEntity::Sbom),
        false,
        false
    ));
    assert!(!crate::endpoints::is_allowed(
        &dummy_entry(ChangeEntity::Advisory),
        false,
        false
    ));
}

// -- Group C: QueryTokenInjector middleware ----------------------------------

async fn echo_auth(req: HttpRequest) -> HttpResponse {
    match req.headers().get("Authorization") {
        Some(val) => HttpResponse::Ok().body(val.to_str().unwrap_or("bad").to_string()),
        None => HttpResponse::NoContent().finish(),
    }
}

#[test(actix_web::test)]
async fn injector_copies_token() {
    let app = actix::init_service(
        App::new().service(
            web::resource("/test")
                .wrap(crate::inject_token::QueryTokenInjector)
                .route(web::get().to(echo_auth)),
        ),
    )
    .await;

    let req = actix::TestRequest::get()
        .uri("/test?token=mytoken")
        .to_request();
    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = actix::read_body(resp).await;
    assert_eq!(body, "Bearer mytoken");
}

#[test(actix_web::test)]
async fn injector_preserves_existing_header() {
    let app = actix::init_service(
        App::new().service(
            web::resource("/test")
                .wrap(crate::inject_token::QueryTokenInjector)
                .route(web::get().to(echo_auth)),
        ),
    )
    .await;

    let req = actix::TestRequest::get()
        .uri("/test?token=other")
        .append_header(("Authorization", "Bearer existing"))
        .to_request();
    let resp = actix::call_service(&app, req).await;
    let body = actix::read_body(resp).await;
    assert_eq!(body, "Bearer existing");
}

#[test(actix_web::test)]
async fn injector_no_token_no_header() {
    let app = actix::init_service(
        App::new().service(
            web::resource("/test")
                .wrap(crate::inject_token::QueryTokenInjector)
                .route(web::get().to(echo_auth)),
        ),
    )
    .await;

    let req = actix::TestRequest::get().uri("/test").to_request();
    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[test(actix_web::test)]
async fn injector_malformed_query_strings() {
    let app = actix::init_service(
        App::new().service(
            web::resource("/test")
                .wrap(crate::inject_token::QueryTokenInjector)
                .route(web::get().to(echo_auth)),
        ),
    )
    .await;

    for uri in ["/test?token", "/test?token=&foo=bar"] {
        let req = actix::TestRequest::get().uri(uri).to_request();
        let resp = actix::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}

// -- Group D: endpoint permission tests -------------------------------------

fn user_with_permissions(perms: &[&str]) -> UserDetails {
    UserDetails {
        id: "test-user".into(),
        permissions: perms.iter().map(|s| s.to_string()).collect(),
    }
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn ws_anonymous_forbidden(ctx: TrustifyContext) {
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = ChangeBroadcaster::new(&db_rw, Duration::from_secs(86400)).expect("broadcaster");
    let authorizer = Authorizer::new(Some(AuthorizerConfig {}));

    let app = actix::init_service(
        App::new()
            .into_utoipa_app()
            .app_data(web::Data::new(authorizer))
            .configure(|svc| {
                crate::endpoints::configure(svc, broadcaster, None);
            })
            .into_app(),
    )
    .await;

    let req = actix::TestRequest::get()
        .uri("/api/v3/notifications")
        .to_request();
    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn ws_no_permissions_forbidden(ctx: TrustifyContext) {
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = ChangeBroadcaster::new(&db_rw, Duration::from_secs(86400)).expect("broadcaster");
    let authorizer = Authorizer::new(Some(AuthorizerConfig {}));

    let app = actix::init_service(
        App::new()
            .into_utoipa_app()
            .app_data(web::Data::new(authorizer))
            .configure(|svc| {
                crate::endpoints::configure(svc, broadcaster, None);
            })
            .into_app(),
    )
    .await;

    let req = actix::TestRequest::get()
        .uri("/api/v3/notifications")
        .to_request()
        .test_auth_details(user_with_permissions(&[]));
    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn ws_read_sbom_accepted(ctx: TrustifyContext) {
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = ChangeBroadcaster::new(&db_rw, Duration::from_secs(86400)).expect("broadcaster");
    let authorizer = Authorizer::new(Some(AuthorizerConfig {}));

    let app = actix::init_service(
        App::new()
            .into_utoipa_app()
            .app_data(web::Data::new(authorizer))
            .configure(|svc| {
                crate::endpoints::configure(svc, broadcaster, None);
            })
            .into_app(),
    )
    .await;

    let req = actix::TestRequest::get()
        .uri("/api/v3/notifications")
        .to_request()
        .test_auth_details(user_with_permissions(&["read.sbom"]));
    let resp = actix::call_service(&app, req).await;
    // Not 403 — passed the permission gate (will fail at WS upgrade since no upgrade headers)
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn ws_read_advisory_accepted(ctx: TrustifyContext) {
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = ChangeBroadcaster::new(&db_rw, Duration::from_secs(86400)).expect("broadcaster");
    let authorizer = Authorizer::new(Some(AuthorizerConfig {}));

    let app = actix::init_service(
        App::new()
            .into_utoipa_app()
            .app_data(web::Data::new(authorizer))
            .configure(|svc| {
                crate::endpoints::configure(svc, broadcaster, None);
            })
            .into_app(),
    )
    .await;

    let req = actix::TestRequest::get()
        .uri("/api/v3/notifications")
        .to_request()
        .test_auth_details(user_with_permissions(&["read.advisory"]));
    let resp = actix::call_service(&app, req).await;
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

// -- Group E: ChangeBroadcaster::fetch_after DB test ------------------------

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn fetch_after_returns_newer_entries(ctx: TrustifyContext) {
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let broadcaster = ChangeBroadcaster::new(&db_rw, Duration::from_secs(86400)).expect("broadcaster");

    // Insert 3 entries with small delays so UUIDv7 ordering is preserved
    record_change(
        &ctx.db,
        ChangeEntity::Sbom,
        Some(Uuid::now_v7()),
        ChangeOperation::Added,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    record_change(
        &ctx.db,
        ChangeEntity::Advisory,
        Some(Uuid::now_v7()),
        ChangeOperation::Added,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    record_change(
        &ctx.db,
        ChangeEntity::Sbom,
        Some(Uuid::now_v7()),
        ChangeOperation::Deleted,
    )
    .await
    .unwrap();

    let all = broadcaster.fetch_after(&Uuid::nil()).await.unwrap();
    assert!(all.len() >= 3);

    let first_cursor = all[all.len() - 3].cursor;
    let after_first = broadcaster.fetch_after(&first_cursor).await.unwrap();
    assert_eq!(after_first.len(), 2);

    let last_cursor = all.last().unwrap().cursor;
    let after_last = broadcaster.fetch_after(&last_cursor).await.unwrap();
    assert!(after_last.is_empty());
}
