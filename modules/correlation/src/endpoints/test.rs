use actix_web::{
    App,
    test::{TestRequest, call_service},
};
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;
use utoipa_actix_web::AppExt;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn empty_sbom_returns_empty_verdicts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
            super::configure(svc, db_ro);
        })
        .into_app();
    let app = actix_web::test::init_service(app).await;

    let id = Uuid::new_v4();
    let req = TestRequest::get()
        .uri(&format!("/v3/correlation/sbom/{id}"))
        .to_request();
    let resp = call_service(&app, req).await;

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(body["verdicts"], serde_json::json!([]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn query_requires_kind(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            let db_ro = trustify_common::db::ReadOnly::new(ctx.db.clone());
            super::configure(svc, db_ro);
        })
        .into_app();
    let app = actix_web::test::init_service(app).await;

    let req = TestRequest::get()
        .uri("/v3/correlation/query?q=6925281924439")
        .to_request();
    assert_eq!(call_service(&app, req).await.status(), 400);

    let req = TestRequest::get()
        .uri("/v3/correlation/query?kind=sku&q=6925281924439")
        .to_request();
    let resp = call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
    assert_eq!(
        body,
        serde_json::json!({
            "query": { "kind": "sku", "value": "6925281924439" },
            "verdicts": [],
        })
    );

    Ok(())
}
