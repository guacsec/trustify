use crate::test::caller;
use actix_http::body::to_bytes;
use actix_http::header::HeaderMap;
use actix_web::{dev::ServiceResponse, http, test::TestRequest};
use http::StatusCode;
use rstest::rstest;
use serde_json::{Value, json};
use test_context::test_context;
use trustify_entity::labels::Labels;
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
    location: Option<String>,
    body: Value,
}

trait FromCreateResponse: Sized {
    fn from_create_response(body: Value, headers: HeaderMap) -> anyhow::Result<Self>;
}

impl FromCreateResponse for GroupResponse {
    fn from_create_response(body: Value, headers: HeaderMap) -> anyhow::Result<Self> {
        Ok(GroupResponse {
            id: body["id"].as_str().expect("must be a string").to_string(),
            etag: headers
                .get(&http::header::ETAG)
                .expect("must have etag header")
                .to_str()
                .expect("etag must be valid string")
                .to_string(),
            location: Some(
                headers
                    .get(&http::header::LOCATION)
                    .expect("location must be present")
                    .to_str()
                    .expect("location must be a string")
                    .to_string(),
            ),
            body,
        })
    }
}

impl FromCreateResponse for () {
    fn from_create_response(_: Value, _: HeaderMap) -> anyhow::Result<Self> {
        Ok(())
    }
}

struct Create {
    name: String,
    parent: Option<String>,
    labels: Labels,
    expected_status: StatusCode,
}

impl Create {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: Default::default(),
            parent: None,
            expected_status: StatusCode::CREATED,
        }
    }

    pub fn parent(mut self, parent: Option<&str>) -> Self {
        self.parent = parent.map(|s| s.to_string());
        self
    }

    pub fn labels(mut self, labels: Labels) -> Self {
        self.labels = labels;
        self
    }

    pub fn expect_status(mut self, status: StatusCode) -> Self {
        self.expected_status = status;
        self
    }

    pub async fn execute<R>(self, app: &impl CallService) -> anyhow::Result<R>
    where
        R: FromCreateResponse,
    {
        let mut request_body = json!({"name": &self.name});
        if let Some(parent_id) = &self.parent {
            request_body["parent"] = json!(parent_id);
        }
        request_body["labels"] = serde_json::to_value(self.labels)?;

        let response = app
            .call_service(
                TestRequest::post()
                    .uri("/api/v2/group/sbom")
                    .set_json(request_body)
                    .to_request(),
            )
            .await;

        assert_eq!(response.status(), self.expected_status);

        let headers = response.headers().clone();
        let body = to_bytes(response.into_body()).await.expect("must decode");
        let body: Value = serde_json::from_slice(&body)?;

        log::info!("body: {body:?}");

        R::from_create_response(body, headers)
    }
}

struct Update {
    id: String,
    name: String,
    parent: Option<String>,
    labels: Option<Labels>,
    if_match_type: IfMatchType,
    etag: String,
    expected_status: StatusCode,
}

impl Update {
    pub fn new(id: impl Into<String>, name: impl Into<String>, etag: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            parent: None,
            labels: None,
            if_match_type: IfMatchType::Correct,
            etag: etag.into(),
            expected_status: StatusCode::NO_CONTENT,
        }
    }

    pub fn parent(mut self, parent: Option<&str>) -> Self {
        self.parent = parent.map(|s| s.to_string());
        self
    }

    pub fn labels(mut self, labels: Labels) -> Self {
        self.labels = Some(labels);
        self
    }

    pub fn if_match(mut self, if_match_type: IfMatchType) -> Self {
        self.if_match_type = if_match_type;
        self
    }

    pub fn expect_status(mut self, status: StatusCode) -> Self {
        self.expected_status = status;
        self
    }

    pub async fn execute(self, app: &impl CallService) -> anyhow::Result<()> {
        let mut update_body = json!({"name": &self.name});

        if let Some(parent_id) = &self.parent {
            update_body["parent"] = json!(parent_id);
        }
        if let Some(labels) = &self.labels {
            update_body["labels"] = serde_json::to_value(labels)?;
        }

        let request = TestRequest::put()
            .uri(&format!("/api/v2/group/sbom/{}", &self.id))
            .set_json(update_body);

        let request = add_if_match(request, self.if_match_type, &self.etag);

        let response = app.call_service(request.to_request()).await;
        assert_eq!(response.status(), self.expected_status);

        Ok(())
    }
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
        location: None,
        body: result,
    })
}

/// Helper to extract response body as JSON
async fn extract_body(response: ServiceResponse) -> Result<Value, anyhow::Error> {
    let body = to_bytes(response.into_body())
        .await
        .expect("should be valid response");
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
    let group: GroupResponse = Create::new("test_group_for_deletion").execute(&app).await?;

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
    None,
    IfMatchType::Correct,
    StatusCode::NO_CONTENT
)]
#[case::invalid_name_empty( // Updates with invalid names fail with 400 Bad Request
    "",
    None,
    IfMatchType::Correct,
    StatusCode::BAD_REQUEST
)]
#[case::invalid_name_whitespace( // Updates with invalid names fail with 400 Bad Request
    "  ",
    None,
    IfMatchType::Correct,
    StatusCode::BAD_REQUEST
)]
#[case::wrong_revision( // Updates with wrong revision fail with 412 Precondition Failed
    "New Name",
    None,
    IfMatchType::Wrong,
    StatusCode::PRECONDITION_FAILED
)]
#[case::update_labels( // Normal labels (and name) update
    "New Name",
    Some(Labels::new().add("foo", "bar")),
    IfMatchType::Correct,
    StatusCode::NO_CONTENT
)]
#[test_log::test(actix_web::test)]
async fn update_group(
    ctx: &TrustifyContext,
    #[case] updated_name: &str,
    #[case] updated_labels: Option<Labels>,
    #[case] if_match_type: IfMatchType,
    #[case] expected_status: StatusCode,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create a group
    let group: GroupResponse = Create::new("test_group").execute(&app).await?;

    // Update the group with the specified If-Match type
    let mut update = Update::new(&group.id, updated_name, &group.etag)
        .if_match(if_match_type)
        .expect_status(expected_status);

    if let Some(labels) = updated_labels.clone() {
        update = update.labels(labels);
    }

    update.execute(&app).await?;

    // Verify the revision changed after successful update
    if expected_status.is_success() {
        let updated_group = get_group_helper(&app, &group.id).await?;

        // Verify the name was updated
        assert_eq!(updated_group.body["name"].as_str(), Some(updated_name));

        // Verify the labels were updated
        assert_eq!(updated_group.body["labels"], json!(updated_labels));

        // Verify the revision changed
        assert_ne!(
            group.etag, updated_group.etag,
            "revision should have changed after update"
        );
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

    Update::new(nonexistent_id, "New Name", "dummy-etag")
        .expect_status(StatusCode::NOT_FOUND)
        .execute(&app)
        .await?;

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
    let group_a: GroupResponse = Create::new("Group A").execute(&app).await?;

    // Create group B with parent A
    let group_b: GroupResponse = Create::new("Group B")
        .parent(Some(&group_a.id))
        .execute(&app)
        .await?;

    // Create group C with parent B
    let group_c: GroupResponse = Create::new("Group C")
        .parent(Some(&group_b.id))
        .execute(&app)
        .await?;

    // Get the current state of group A to obtain its latest ETag
    let group_a = get_group_helper(&app, &group_a.id).await?;

    // Try to update group A to have C as its parent (creating a cycle: A -> C -> B -> A)
    Update::new(&group_a.id, "Group A", &group_a.etag)
        .parent(Some(&group_c.id))
        .expect_status(StatusCode::CONFLICT)
        .execute(&app)
        .await?;

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
    let group: GroupResponse = Create::new("Self-Parent Group").execute(&app).await?;

    // Get the current state to obtain its latest ETag
    let group = get_group_helper(&app, &group.id).await?;

    // Try to update the group to have itself as parent
    Update::new(&group.id, "Self-Parent Group", &group.etag)
        .parent(Some(&group.id))
        .expect_status(StatusCode::CONFLICT)
        .execute(&app)
        .await?;

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
        Some(Create::new(name).execute::<GroupResponse>(&app).await?.id)
    } else {
        None
    };

    // Create first group with name "Duplicate"
    let _group1: GroupResponse = Create::new("Duplicate")
        .parent(parent_id.as_deref())
        .execute(&app)
        .await?;

    // Try to create second group with the same name at the same level
    // Should return 409 Conflict because the name is already used at this level
    let _result: () = Create::new("Duplicate")
        .parent(parent_id.as_deref())
        .expect_status(StatusCode::CONFLICT)
        .execute(&app)
        .await?;

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
    let parent_a: GroupResponse = Create::new("Parent A").execute(&app).await?;
    let parent_b: GroupResponse = Create::new("Parent B").execute(&app).await?;

    // Create group with name "Child" under parent A
    let _child_a: GroupResponse = Create::new("Child")
        .parent(Some(&parent_a.id))
        .execute(&app)
        .await?;

    // Create group with same name "Child" under parent B - should succeed
    let _child_b_result: GroupResponse = Create::new("Child")
        .parent(Some(&parent_b.id))
        .execute(&app)
        .await?;

    // Also verify we can create a "Child" at root level
    let _child_root_result: GroupResponse = Create::new("Child").execute(&app).await?;

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
        Some(Create::new(name).execute::<GroupResponse>(&app).await?.id)
    } else {
        None
    };

    // Create two groups with different names at the same level
    let _group1: GroupResponse = Create::new("Group One")
        .parent(parent_id.as_deref())
        .execute(&app)
        .await?;
    let group2: GroupResponse = Create::new("Group Two")
        .parent(parent_id.as_deref())
        .execute(&app)
        .await?;

    // Get current state of group2
    let group2 = get_group_helper(&app, &group2.id).await?;

    // Try to update group2 to have the same name as group1
    Update::new(&group2.id, "Group One", &group2.etag)
        .parent(parent_id.as_deref())
        .expect_status(StatusCode::CONFLICT)
        .execute(&app)
        .await?;

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
    let parent_a: GroupResponse = Create::new("Parent A").execute(&app).await?;
    let parent_b: GroupResponse = Create::new("Parent B").execute(&app).await?;

    // Create group with name "Shared Name" under parent A
    let _child_a: GroupResponse = Create::new("Shared Name")
        .parent(Some(&parent_a.id))
        .execute(&app)
        .await?;

    // Create group with same name "Shared Name" under parent B
    let child_b: GroupResponse = Create::new("Shared Name")
        .parent(Some(&parent_b.id))
        .execute(&app)
        .await?;

    // Get current state of child_b
    let child_b = get_group_helper(&app, &child_b.id).await?;

    // Try to move child_b to parent A, which would create a conflict
    Update::new(&child_b.id, "Shared Name", &child_b.etag)
        .parent(Some(&parent_a.id))
        .expect_status(StatusCode::CONFLICT)
        .execute(&app)
        .await?;

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
    Create::new("Shared Name").execute::<()>(&app).await?;

    // Create a parent group
    let parent: GroupResponse = Create::new("Parent").execute(&app).await?;

    // Create a group with the same name under the parent
    let child: GroupResponse = Create::new("Shared Name")
        .parent(Some(&parent.id))
        .execute(&app)
        .await?;

    // Get current state of child
    let child = get_group_helper(&app, &child.id).await?;

    // Try to move child to root level by removing its parent
    Update::new(&child.id, "Shared Name", &child.etag)
        .parent(None)
        .expect_status(StatusCode::CONFLICT)
        .execute(&app)
        .await?;

    Ok(())
}
