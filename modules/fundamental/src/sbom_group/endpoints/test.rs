use crate::test::caller;
use actix_http::body::to_bytes;
use actix_web::{http, test::TestRequest};
use http::StatusCode;
use rstest::rstest;
use serde_json::{Value, json};
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

#[test_context(TrustifyContext)]
#[rstest]
#[case(
    json!({"name": "foo"}),
    StatusCode::CREATED,
)]
#[case(
    json!({"name": ""}),
    StatusCode::BAD_REQUEST,
)]
#[test_log::test(actix_web::test)]
async fn create_group(
    ctx: &TrustifyContext,
    #[case] request: Value,
    #[case] expected_status: StatusCode,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(request)
                .to_request(),
        )
        .await;

    let status = response.status();
    let headers = response.headers().clone();

    let body = to_bytes(response.into_body())
        .await
        .expect("should be valid response");
    let v: Value = serde_json::from_slice(&body)?;

    log::info!("{v:#?}");

    // now assert

    assert_eq!(status, expected_status);

    if status.is_success() {
        let id = v["id"].as_str().expect("must be a string");
        assert_eq!(
            headers
                .get(&http::header::LOCATION)
                .map(|s| s.to_str().expect("must be a string")),
            Some(format!("/api/v2/group/sbom/{id}").as_str()),
            "must return a relative URL to the group"
        );
        assert!(
            headers.contains_key(http::header::ETAG),
            "must have etag value"
        )
    }

    Ok(())
}
