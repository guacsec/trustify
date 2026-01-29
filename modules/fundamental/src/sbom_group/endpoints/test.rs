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

fn if_match(request: TestRequest, if_match_type: IfMatchType, etag: &str) -> TestRequest {
    match if_match_type {
        IfMatchType::Correct => request.insert_header((http::header::IF_MATCH, etag)),
        IfMatchType::Wildcard => request.insert_header((http::header::IF_MATCH, "*")),
        IfMatchType::Missing => {
            // Don't add any If-Match header
            request
        }
        IfMatchType::Wrong => {
            request.insert_header((http::header::IF_MATCH, "\"wrong-revision-123\""))
        }
    }
}

/// Test updating an SBOM group with various scenarios.
#[test_context(TrustifyContext)]
#[rstest]
#[case::normal_update( // Normal updates with valid data and correct revision succeed and change the revision
    "Updated Group Name",
    IfMatchType::Correct,
    StatusCode::NO_CONTENT
)]
#[case::invalid_name_empty( // Updates with invalid names fail with 400 Bad Request
    "",
    IfMatchType::Correct,
    StatusCode::BAD_REQUEST
)]
#[case::invalid_name_whitespace( // Updates with invalid names fail with 400 Bad Request
    "  ",
    IfMatchType::Correct,
    StatusCode::BAD_REQUEST
)]
#[case::wrong_revision( // Updates with wrong revision fail with 412 Precondition Failed
    "New Name",
    IfMatchType::Wrong,
    StatusCode::PRECONDITION_FAILED
)]
#[test_log::test(actix_web::test)]
async fn update_group(
    ctx: &TrustifyContext,
    #[case] updated_name: &str,
    #[case] if_match_type: IfMatchType,
    #[case] expected_status: StatusCode,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // First, create a group with a valid name
    let create_request = json!({"name": "test_group"});

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

    // Now update the group
    let update_request = json!({"name": updated_name});

    let update_req = TestRequest::put().uri(&format!("/api/v2/group/sbom/{}", group_id));
    let update_req = if_match(update_req, if_match_type, etag);

    let update_response = app
        .call_service(update_req.set_json(update_request).to_request())
        .await;

    let update_status = update_response.status();
    assert_eq!(update_status, expected_status);

    // If requested, verify the revision changed after update
    if update_status.is_success() {
        let get_response = app
            .call_service(
                TestRequest::get()
                    .uri(&format!("/api/v2/group/sbom/{}", group_id))
                    .to_request(),
            )
            .await;

        let get_status = get_response.status();
        let get_headers = get_response.headers().clone();

        assert_eq!(get_status, StatusCode::OK);

        let get_body = to_bytes(get_response.into_body())
            .await
            .expect("should be valid response");
        let get_result: Value = serde_json::from_slice(&get_body)?;

        // Verify the name was updated
        assert_eq!(get_result["name"].as_str(), Some(updated_name));

        // Verify the revision changed
        let new_etag = get_headers
            .get(&http::header::ETAG)
            .expect("must have etag header")
            .to_str()
            .expect("etag must be valid string");

        assert_ne!(etag, new_etag, "revision should have changed after update");
    }

    Ok(())
}

/// Test updating a non-existent SBOM group.
///
/// Attempts to update a group with a non-existent ID.
/// Should return 404 Not Found.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn update_nonexistent_group(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let nonexistent_id = "nonexistent-group-id";
    let update_request = json!({"name": "New Name"});

    let update_response = app
        .call_service(
            TestRequest::put()
                .uri(&format!("/api/v2/group/sbom/{}", nonexistent_id))
                .set_json(update_request)
                .to_request(),
        )
        .await;

    let update_status = update_response.status();
    assert_eq!(update_status, StatusCode::NOT_FOUND);

    Ok(())
}

/// Test creating a cycle in the parent hierarchy.
///
/// Creates a chain of groups (A -> B -> C) and then attempts to update group A
/// to have C as its parent, which would create a cycle (A -> C -> B -> A).
/// This should return 409 Conflict.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn create_parent_cycle(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create group A (no parent)
    let create_a = json!({"name": "Group A"});
    let response_a = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(create_a)
                .to_request(),
        )
        .await;

    assert_eq!(response_a.status(), StatusCode::CREATED);
    let body_a = to_bytes(response_a.into_body()).await.expect("must decode");
    let result_a: Value = serde_json::from_slice(&body_a)?;
    let group_a_id = result_a["id"].as_str().expect("must be a string");

    // Create group B with parent A
    let create_b = json!({"name": "Group B", "parent": group_a_id});
    let response_b = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(create_b)
                .to_request(),
        )
        .await;

    assert_eq!(response_b.status(), StatusCode::CREATED);
    let body_b = to_bytes(response_b.into_body()).await.expect("must decode");
    let result_b: Value = serde_json::from_slice(&body_b)?;
    let group_b_id = result_b["id"].as_str().expect("must be a string");

    // Create group C with parent B
    let create_c = json!({"name": "Group C", "parent": group_b_id});
    let response_c = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(create_c)
                .to_request(),
        )
        .await;

    assert_eq!(response_c.status(), StatusCode::CREATED);
    let body_c = to_bytes(response_c.into_body()).await.expect("must decode");
    let result_c: Value = serde_json::from_slice(&body_c)?;
    let group_c_id = result_c["id"].as_str().expect("must be a string");

    // Get the current state of group A to obtain its ETag
    let get_response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom/{}", group_a_id))
                .to_request(),
        )
        .await;

    assert_eq!(get_response.status(), StatusCode::OK);
    let etag = get_response
        .headers()
        .get(&http::header::ETAG)
        .expect("must have etag header")
        .to_str()
        .expect("etag must be valid string");

    // Now try to update group A to have C as its parent (creating a cycle: A -> C -> B -> A)
    let update_a = json!({"name": "Group A", "parent": group_c_id});
    let update_response = app
        .call_service(
            TestRequest::put()
                .uri(&format!("/api/v2/group/sbom/{}", group_a_id))
                .insert_header((http::header::IF_MATCH, etag))
                .set_json(update_a)
                .to_request(),
        )
        .await;

    // Should return 409 Conflict because this would create a cycle
    assert_eq!(
        update_response.status(),
        StatusCode::CONFLICT,
        "Creating a parent cycle should return 409 Conflict"
    );

    Ok(())
}

/// Test updating a group to set its parent to itself.
///
/// Creates a group and then attempts to update it to have itself as its parent,
/// which would create a self-referential cycle. This should return 409 Conflict.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn update_group_parent_to_itself(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create a group
    let create_request = json!({"name": "Self-Parent Group"});
    let create_response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(create_request)
                .to_request(),
        )
        .await;

    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body = to_bytes(create_response.into_body()).await.expect("must decode");
    let create_result: Value = serde_json::from_slice(&create_body)?;
    let group_id = create_result["id"].as_str().expect("must be a string");

    // Get the current state to obtain its ETag
    let get_response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom/{}", group_id))
                .to_request(),
        )
        .await;

    assert_eq!(get_response.status(), StatusCode::OK);
    let etag = get_response
        .headers()
        .get(&http::header::ETAG)
        .expect("must have etag header")
        .to_str()
        .expect("etag must be valid string");

    // Try to update the group to have itself as parent
    let update_request = json!({"name": "Self-Parent Group", "parent": group_id});
    let update_response = app
        .call_service(
            TestRequest::put()
                .uri(&format!("/api/v2/group/sbom/{}", group_id))
                .insert_header((http::header::IF_MATCH, etag))
                .set_json(update_request)
                .to_request(),
        )
        .await;

    // Should return 409 Conflict because a group cannot be its own parent
    assert_eq!(
        update_response.status(),
        StatusCode::CONFLICT,
        "Setting a group as its own parent should return 409 Conflict"
    );

    Ok(())
}
