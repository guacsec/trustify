use crate::test::caller;
use actix_http::body::to_bytes;
use actix_web::{http, test::TestRequest};
use http::StatusCode;
use rstest::rstest;
use serde_json::{Value, json};
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

#[derive(Debug, Clone, Copy)]
enum IfMatchType {
    Wildcard,
    Correct,
    Missing,
    Wrong,
}

/// Test creating an SBOM group with various inputs.
///
/// Tests both successful creation with a valid name and failure cases with invalid inputs.
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

/// Test creating and then deleting an SBOM group with different If-Match scenarios.
///
/// Verifies that:
/// - Successful deletions (wildcard, correct revision, missing header) result in the group being gone
/// - Failed deletions (wrong revision) result in the group still existing
#[test_context(TrustifyContext)]
#[rstest]
#[case::wildcard(IfMatchType::Wildcard, StatusCode::NO_CONTENT)] // Using "*" as If-Match header (should accept any revision)
#[case::correct_revision(IfMatchType::Correct, StatusCode::NO_CONTENT)] // Using the actual ETag returned from creation
#[case::missing_header(IfMatchType::Missing, StatusCode::NO_CONTENT)] // Omitting the If-Match header entirely
#[case::wrong_revision(IfMatchType::Wrong, StatusCode::PRECONDITION_FAILED)] // Using an incorrect ETag (should fail with 412 Precondition Failed)
#[test_log::test(actix_web::test)]
async fn create_and_delete_group(
    ctx: &TrustifyContext,
    #[case] if_match_type: IfMatchType,
    #[case] expected_status: StatusCode,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // First, create a group
    let create_request = json!({"name": "test_group_for_deletion"});

    let create_response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(create_request)
                .to_request(),
        )
        .await;

    let create_status = create_response.status();
    let create_headers = create_response.headers().clone();

    assert_eq!(create_status, StatusCode::CREATED);

    let create_body = to_bytes(create_response.into_body())
        .await
        .expect("should be valid response");
    let create_result: Value = serde_json::from_slice(&create_body)?;

    let group_id = create_result["id"].as_str().expect("must be a string");
    let etag = create_headers
        .get(&http::header::ETAG)
        .expect("must have etag header")
        .to_str()
        .expect("etag must be valid string");

    // Now delete the group
    let mut delete_request = TestRequest::delete().uri(&format!("/api/v2/group/sbom/{}", group_id));

    match if_match_type {
        IfMatchType::Correct => {
            delete_request = delete_request.insert_header((http::header::IF_MATCH, etag));
        }
        IfMatchType::Wildcard => {
            delete_request = delete_request.insert_header((http::header::IF_MATCH, "*"));
        }
        IfMatchType::Missing => {
            // Don't add any If-Match header
        }
        IfMatchType::Wrong => {
            delete_request =
                delete_request.insert_header((http::header::IF_MATCH, "\"wrong-revision-123\""));
        }
    }

    let delete_response = app.call_service(delete_request.to_request()).await;

    let delete_status = delete_response.status();
    assert_eq!(delete_status, expected_status);

    // Verify the group's existence after the delete attempt
    let get_response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom/{}", group_id))
                .to_request(),
        )
        .await;

    let get_status = get_response.status();

    if expected_status.is_success() {
        // Delete succeeded, group should not exist
        assert_eq!(get_status, StatusCode::NOT_FOUND);
    } else {
        // Delete failed, group should still exist
        assert_eq!(get_status, StatusCode::OK);
    }

    Ok(())
}

/// Test deleting an SBOM group that doesn't exist.
///
/// Attempts to delete a group with a non-existent ID.
/// According to the endpoint documentation, this should return 204 No Content
/// (the operation is idempotent - the desired state is achieved).
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn delete_nonexistent_group(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Try to delete a group that doesn't exist
    let nonexistent_id = "nonexistent-group-id";
    let delete_response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/group/sbom/{}", nonexistent_id))
                .insert_header((http::header::IF_MATCH, "*"))
                .to_request(),
        )
        .await;

    let delete_status = delete_response.status();
    // According to the endpoint documentation, deleting a non-existent group should return 204
    assert_eq!(delete_status, StatusCode::NO_CONTENT);

    Ok(())
}
