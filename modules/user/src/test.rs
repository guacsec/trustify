#![cfg(test)]

use crate::service::{Error, UserPreferenceService};
use actix_http::header;
use actix_web::{App, http::StatusCode, test as actix};
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_common::model::Revisioned;
use trustify_test_context::TrustifyContext;
use trustify_test_context::auth::TestAuthentication;
use utoipa_actix_web::AppExt;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
async fn collision(ctx: TrustifyContext) -> anyhow::Result<()> {
    let service = UserPreferenceService::new(ctx.db.clone());

    // initially it must be gone

    let result = service.get("user-a".into(), "key-a".into()).await?;
    assert!(result.is_none());

    // setting one with an invalid revision should rais a mid air collision

    let result = service
        .set("user-a".into(), "key-a".into(), Some("a"), json!({"a": 1}))
        .await;
    assert!(matches!(result, Result::Err(Error::MidAirCollision)));

    // now set a proper one

    service
        .set("user-a".into(), "key-a".into(), None, json!({"a": 1}))
        .await?;

    //  we should be able to get it

    let result = service.get("user-a".into(), "key-a".into()).await?;
    assert!(matches!(
        result,
        Some(Revisioned {
            value: serde_json::Value::Object(data),
            revision: _
        }) if data["a"] == 1
    ));

    // try setting one again with an invalid revision

    let result = service
        .set("user-a".into(), "key-a".into(), Some("a"), json!({"a": 1}))
        .await;
    assert!(matches!(result, Result::Err(Error::MidAirCollision)));

    // must not change the data

    let result = service.get("user-a".into(), "key-a".into()).await?;
    assert!(matches!(
        result,
        Some(Revisioned {
            value: serde_json::Value::Object(data),
            revision: _
        }) if data["a"] == 1
    ));

    // now let's update the data

    service
        .set("user-a".into(), "key-a".into(), None, json!({"a": 2}))
        .await?;

    // it should change

    let result = service.get("user-a".into(), "key-a".into()).await?.unwrap();
    assert!(matches!(
        result,
        Revisioned {
            value: serde_json::Value::Object(data),
            revision: _
        } if data["a"] == 2
    ));

    // now let's update the data with a proper revision

    service
        .set(
            "user-a".into(),
            "key-a".into(),
            Some(&result.revision),
            json!({"a": 3}),
        )
        .await?;

    // check result, must change

    let result = service.get("user-a".into(), "key-a".into()).await?.unwrap();
    let Revisioned { value, revision } = result;
    assert!(matches!(
        value,
        serde_json::Value::Object(data) if data["a"] == 3
    ));

    // try deleting wrong revision, must fail

    let result = service
        .delete("user-a".into(), "key-a".into(), Some("a"))
        .await;
    assert!(matches!(result, Result::Err(Error::MidAirCollision)));

    // try deleting correct revision, must succeed

    let result = service
        .delete("user-a".into(), "key-a".into(), Some(&revision))
        .await;
    assert!(matches!(result, Result::Ok(true)));

    // try deleting correct revision again, must succeed, but return false

    let result = service
        .delete("user-a".into(), "key-a".into(), Some(&revision))
        .await;
    assert!(matches!(result, Result::Ok(false)));

    // try deleting any revision, must succeed, but return false

    let result = service.delete("user-a".into(), "key-a".into(), None).await;
    assert!(matches!(result, Result::Ok(false)));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn wrong_rev(ctx: TrustifyContext) {
    let db = &ctx.db;
    let app = actix::init_service(
        App::new()
            .into_utoipa_app()
            .service(
                utoipa_actix_web::scope("/api")
                    .configure(|svc| super::endpoints::configure(svc, db.clone())),
            )
            .into_app(),
    )
    .await;

    // create one

    let req = actix::TestRequest::put()
        .uri("/api/v2/userPreference/foo")
        .set_json(json!({"a": 1}))
        .to_request()
        .test_auth("user-a");

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // try to update the wrong one

    let req = actix::TestRequest::put()
        .uri("/api/v2/userPreference/foo")
        .append_header((header::IF_MATCH, r#""a""#))
        .set_json(json!({"a": 2}))
        .to_request()
        .test_auth("user-a");

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}
