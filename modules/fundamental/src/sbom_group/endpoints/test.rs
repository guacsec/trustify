use crate::test::caller;
use actix_http::body::to_bytes;
use actix_web::{dev::ServiceResponse, http, test::TestRequest};
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

/// Helper struct to hold group creation response data
struct GroupResponse {
    id: String,
    etag: String,
    body: Value,
}

/// Helper to create a group and extract common response data
async fn create_group_helper(
    app: &impl CallService,
    name: &str,
    parent: Option<&str>,
) -> Result<GroupResponse, anyhow::Error> {
    let mut request_body = json!({"name": name});
    if let Some(parent_id) = parent {
        request_body["parent"] = json!(parent_id);
    }

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(request_body)
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::CREATED);

    let headers = response.headers().clone();
    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;

    Ok(GroupResponse {
        id: result["id"].as_str().expect("must be a string").to_string(),
        etag: headers
            .get(&http::header::ETAG)
            .expect("must have etag header")
            .to_str()
            .expect("etag must be valid string")
            .to_string(),
        body: result,
    })
}

/// Helper to get a group and extract etag
async fn get_group_helper(
    app: &impl CallService,
    id: &str,
) -> Result<GroupResponse, anyhow::Error> {
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom/{}", id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers().clone();
    let body = to_bytes(response.into_body()).await.expect("must decode");
    let result: Value = serde_json::from_slice(&body)?;

    Ok(GroupResponse {
        id: id.to_string(),
        etag: headers
            .get(&http::header::ETAG)
            .expect("must have etag header")
            .to_str()
            .expect("etag must be valid string")
            .to_string(),
        body: result,
    })
}

/// Helper to extract response body as JSON
async fn extract_body(response: ServiceResponse) -> Result<Value, anyhow::Error> {
    let body = to_bytes(response.into_body()).await.expect("should be valid response");
    Ok(serde_json::from_slice(&body)?)
}

/// Helper to add If-Match header based on type
fn add_if_match(request: TestRequest, if_match_type: IfMatchType, etag: &str) -> TestRequest {
    match if_match_type {
        IfMatchType::Correct => request.insert_header((http::header::IF_MATCH, etag)),
        IfMatchType::Wildcard => request.insert_header((http::header::IF_MATCH, "*")),
        IfMatchType::Missing => request,
        IfMatchType::Wrong => {
            request.insert_header((http::header::IF_MATCH, "\"wrong-revision-123\""))
        }
    }
}

/// Helper to update a group with name and optional parent
async fn update_group_helper(
    app: &impl CallService,
    id: &str,
    etag: &str,
    name: &str,
    parent: Option<&str>,
) -> ServiceResponse {
    let mut update_request = json!({"name": name});
    if let Some(parent_id) = parent {
        update_request["parent"] = json!(parent_id);
    }

    app.call_service(
        TestRequest::put()
            .uri(&format!("/api/v2/group/sbom/{}", id))
            .insert_header((http::header::IF_MATCH, etag))
            .set_json(update_request)
            .to_request(),
    )
    .await
}

/// Helper to update a group and expect a specific status code
async fn update_group_expect_status(
    app: &impl CallService,
    id: &str,
    etag: &str,
    name: &str,
    parent: Option<&str>,
    expected_status: StatusCode,
    error_message: &str,
) {
    let response = update_group_helper(app, id, etag, name, parent).await;
    assert_eq!(response.status(), expected_status, "{}", error_message);
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
    let body = extract_body(response).await?;

    log::info!("{body:#?}");

    assert_eq!(status, expected_status);

    if status.is_success() {
        let id = body["id"].as_str().expect("must be a string");
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

    // Create a group
    let group = create_group_helper(&app, "test_group_for_deletion", None).await?;

    // Delete the group
    let delete_request = TestRequest::delete().uri(&format!("/api/v2/group/sbom/{}", group.id));
    let delete_request = add_if_match(delete_request, if_match_type, &group.etag);

    let delete_response = app.call_service(delete_request.to_request()).await;
    assert_eq!(delete_response.status(), expected_status);

    // Verify the group's existence after the delete attempt
    let get_response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom/{}", group.id))
                .to_request(),
        )
        .await;

    if expected_status.is_success() {
        // Delete succeeded, group should not exist
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
    } else {
        // Delete failed, group should still exist
        assert_eq!(get_response.status(), StatusCode::OK);
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

    // Create a group
    let group = create_group_helper(&app, "test_group", None).await?;

    // Update the group with the specified If-Match type
    let update_request = json!({"name": updated_name});
    let update_req = TestRequest::put().uri(&format!("/api/v2/group/sbom/{}", group.id));
    let update_req = add_if_match(update_req, if_match_type, &group.etag);

    let update_response = app
        .call_service(update_req.set_json(update_request).to_request())
        .await;

    assert_eq!(update_response.status(), expected_status);

    // Verify the revision changed after successful update
    if expected_status.is_success() {
        let updated_group = get_group_helper(&app, &group.id).await?;

        // Verify the name was updated
        assert_eq!(updated_group.body["name"].as_str(), Some(updated_name));

        // Verify the revision changed
        assert_ne!(group.etag, updated_group.etag, "revision should have changed after update");
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
    let group_a = create_group_helper(&app, "Group A", None).await?;

    // Create group B with parent A
    let group_b = create_group_helper(&app, "Group B", Some(&group_a.id)).await?;

    // Create group C with parent B
    let group_c = create_group_helper(&app, "Group C", Some(&group_b.id)).await?;

    // Get the current state of group A to obtain its latest ETag
    let group_a = get_group_helper(&app, &group_a.id).await?;

    // Try to update group A to have C as its parent (creating a cycle: A -> C -> B -> A)
    update_group_expect_status(
        &app,
        &group_a.id,
        &group_a.etag,
        "Group A",
        Some(&group_c.id),
        StatusCode::CONFLICT,
        "Creating a parent cycle should return 409 Conflict",
    )
    .await;

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
    let group = create_group_helper(&app, "Self-Parent Group", None).await?;

    // Get the current state to obtain its latest ETag
    let group = get_group_helper(&app, &group.id).await?;

    // Try to update the group to have itself as parent
    update_group_expect_status(
        &app,
        &group.id,
        &group.etag,
        "Self-Parent Group",
        Some(&group.id),
        StatusCode::CONFLICT,
        "Setting a group as its own parent should return 409 Conflict",
    )
    .await;

    Ok(())
}

/// Test creating duplicate group names at the same level.
///
/// Verifies that group names must be unique within the same parent context.
/// Tests both root level (no parent) and under a specific parent.
#[test_context(TrustifyContext)]
#[rstest]
#[case::duplicate_at_root(None)] // Two groups with same name at root level
#[case::duplicate_under_parent(Some("parent_group"))] // Two groups with same name under same parent
#[test_log::test(actix_web::test)]
async fn create_duplicate_group_names(
    ctx: &TrustifyContext,
    #[case] parent_name: Option<&str>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create parent group if needed
    let parent_id = if let Some(name) = parent_name {
        Some(create_group_helper(&app, name, None).await?.id)
    } else {
        None
    };

    // Create first group with name "Duplicate"
    let _group1 = create_group_helper(&app, "Duplicate", parent_id.as_deref()).await?;

    // Try to create second group with the same name at the same level
    let mut request_body = json!({"name": "Duplicate"});
    if let Some(parent) = &parent_id {
        request_body["parent"] = json!(parent);
    }

    let response = app
        .call_service(
            TestRequest::post()
                .uri("/api/v2/group/sbom")
                .set_json(request_body)
                .to_request(),
        )
        .await;

    // Should return 409 Conflict because the name is already used at this level
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "Creating a group with duplicate name at the same level should return 409 Conflict"
    );

    Ok(())
}

/// Test that groups with the same name can exist under different parents.
///
/// Verifies that the uniqueness constraint is scoped to the parent level,
/// allowing groups with identical names in different branches of the hierarchy.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn create_same_name_different_parents(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create two parent groups
    let parent_a = create_group_helper(&app, "Parent A", None).await?;
    let parent_b = create_group_helper(&app, "Parent B", None).await?;

    // Create group with name "Child" under parent A
    let _child_a = create_group_helper(&app, "Child", Some(&parent_a.id)).await?;

    // Create group with same name "Child" under parent B - should succeed
    let child_b_result = create_group_helper(&app, "Child", Some(&parent_b.id)).await;

    assert!(
        child_b_result.is_ok(),
        "Creating groups with same name under different parents should succeed"
    );

    // Also verify we can create a "Child" at root level
    let child_root_result = create_group_helper(&app, "Child", None).await;

    assert!(
        child_root_result.is_ok(),
        "Creating a group with same name at root level should succeed when others are under parents"
    );

    Ok(())
}

/// Test updating a group name to conflict with a sibling.
///
/// Creates two groups at the same level with different names, then attempts
/// to update one to have the same name as the other. This should fail.
#[test_context(TrustifyContext)]
#[rstest]
#[case::update_at_root(None)] // Update at root level
#[case::update_under_parent(Some("parent_group"))] // Update under a parent
#[test_log::test(actix_web::test)]
async fn update_to_duplicate_name(
    ctx: &TrustifyContext,
    #[case] parent_name: Option<&str>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create parent group if needed
    let parent_id = if let Some(name) = parent_name {
        Some(create_group_helper(&app, name, None).await?.id)
    } else {
        None
    };

    // Create two groups with different names at the same level
    let _group1 = create_group_helper(&app, "Group One", parent_id.as_deref()).await?;
    let group2 = create_group_helper(&app, "Group Two", parent_id.as_deref()).await?;

    // Get current state of group2
    let group2 = get_group_helper(&app, &group2.id).await?;

    // Try to update group2 to have the same name as group1
    update_group_expect_status(
        &app,
        &group2.id,
        &group2.etag,
        "Group One",
        parent_id.as_deref(),
        StatusCode::CONFLICT,
        "Updating a group to have the same name as a sibling should return 409 Conflict",
    )
    .await;

    Ok(())
}

/// Test changing a group's parent to create a name conflict.
///
/// Creates groups with the same name under different parents, then attempts
/// to move one group to the other parent's level, which would create a conflict.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn update_parent_to_create_name_conflict(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create two parent groups
    let parent_a = create_group_helper(&app, "Parent A", None).await?;
    let parent_b = create_group_helper(&app, "Parent B", None).await?;

    // Create group with name "Shared Name" under parent A
    let _child_a = create_group_helper(&app, "Shared Name", Some(&parent_a.id)).await?;

    // Create group with same name "Shared Name" under parent B
    let child_b = create_group_helper(&app, "Shared Name", Some(&parent_b.id)).await?;

    // Get current state of child_b
    let child_b = get_group_helper(&app, &child_b.id).await?;

    // Try to move child_b to parent A, which would create a conflict
    update_group_expect_status(
        &app,
        &child_b.id,
        &child_b.etag,
        "Shared Name",
        Some(&parent_a.id),
        StatusCode::CONFLICT,
        "Moving a group to a parent that already has a child with the same name should return 409 Conflict",
    )
    .await;

    Ok(())
}

/// Test changing a group's parent to root level to create a name conflict.
///
/// Creates a group at root level and another under a parent with the same name,
/// then attempts to move the child to root level, which would create a conflict.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn update_parent_to_root_create_conflict(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create a group at root level
    let _root_group = create_group_helper(&app, "Shared Name", None).await?;

    // Create a parent group
    let parent = create_group_helper(&app, "Parent", None).await?;

    // Create a group with the same name under the parent
    let child = create_group_helper(&app, "Shared Name", Some(&parent.id)).await?;

    // Get current state of child
    let child = get_group_helper(&app, &child.id).await?;

    // Try to move child to root level by removing its parent
    update_group_expect_status(
        &app,
        &child.id,
        &child.etag,
        "Shared Name",
        None,
        StatusCode::CONFLICT,
        "Moving a group to root level when a group with the same name exists at root should return 409 Conflict",
    )
    .await;

    Ok(())
}
