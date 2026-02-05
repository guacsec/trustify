use crate::{sbom_group::model::GroupDetails, test::caller};
use actix_http::{body::to_bytes, header::HeaderMap};
use actix_web::{http, test::TestRequest};
use anyhow::Context;
use http::StatusCode;
use rstest::rstest;
use serde_json::{Value, json};
use std::collections::HashMap;
use test_context::test_context;
use trustify_common::model::PaginatedResults;
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
    fn from_create_response(body: Value, headers: HeaderMap) -> Self;
}

impl FromCreateResponse for GroupResponse {
    fn from_create_response(body: Value, headers: HeaderMap) -> Self {
        let result: anyhow::Result<GroupResponse> =
            FromCreateResponse::from_create_response(body, headers);
        result.expect("failed to parse response")
    }
}

impl FromCreateResponse for anyhow::Result<GroupResponse> {
    fn from_create_response(body: Value, headers: HeaderMap) -> Self {
        let location = headers
            .get(&http::header::LOCATION)
            .context("location must be present")?
            .to_str()
            .context("location must be a string")?
            .to_string();

        let id = body["id"].as_str().context("must be a string")?.to_string();

        assert_eq!(
            location,
            format!("/api/v2/group/sbom/{id}").as_str(),
            "must return a relative URL to the group"
        );

        Ok(GroupResponse {
            id,
            etag: headers
                .get(&http::header::ETAG)
                .context("must have etag header")?
                .to_str()
                .context("etag must be valid string")
                .map(ToString::to_string)?,
            location: Some(location),
            body,
        })
    }
}

impl FromCreateResponse for () {
    fn from_create_response(_: Value, _: HeaderMap) -> Self {}
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

        Ok(R::from_create_response(body, headers))
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
#[case("foo", Default::default(), StatusCode::CREATED)]
#[case("", Default::default(), StatusCode::BAD_REQUEST)]
#[case("foo", Labels::new().add("foo", "bar"), StatusCode::CREATED)]
#[case("foo", Labels::new().add("", "bar"), StatusCode::BAD_REQUEST)]
#[test_log::test(actix_web::test)]
async fn create_group(
    ctx: &TrustifyContext,
    #[case] name: &str,
    #[case] labels: Labels,
    #[case] expected_status: StatusCode,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let group: anyhow::Result<GroupResponse> = Create::new(name)
        .expect_status(expected_status)
        .labels(labels)
        .execute(&app)
        .await?;

    if expected_status.is_success() {
        let group = group.expect("Must have a result");

        // check if the location is working

        let req = TestRequest::get().uri(&group.location.expect("must have location"));
        let read = app.call_and_read_body_json::<Value>(req.to_request()).await;
        assert_eq!(read["id"].as_str(), Some(group.id.as_str()));
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

/// Test deleting an SBOM group that has child groups.
///
/// Attempts to delete a parent group when it has children.
/// This should return 409 Conflict because the group cannot be deleted
/// while it still has child groups.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn delete_group_with_children(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // Create a parent group
    let parent: GroupResponse = Create::new("Parent Group").execute(&app).await?;

    // Create a child group under the parent
    let _child: GroupResponse = Create::new("Child Group")
        .parent(Some(&parent.id))
        .execute(&app)
        .await?;

    // Try to delete the parent group
    let delete_response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v2/group/sbom/{}", parent.id))
                .insert_header((http::header::IF_MATCH, "*"))
                .to_request(),
        )
        .await;

    // Should return 409 Conflict because the group has children
    assert_eq!(delete_response.status(), StatusCode::CONFLICT);

    // Verify the parent group still exists
    get_group_helper(&app, &parent.id).await?;

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

#[derive(Debug, PartialEq, Eq)]
struct Item {
    id: &'static [&'static str],
    name: &'static str,
    labels: HashMap<&'static str, &'static str>,
    total_groups: Option<u64>,
    total_sboms: Option<u64>,
    parents: Option<&'static [&'static str]>,
}

impl Item {
    pub fn new(id: &'static [&'static str]) -> Self {
        Self {
            id,
            name: id[id.len() - 1],
            labels: HashMap::new(),
            total_groups: None,
            total_sboms: None,
            parents: None,
        }
    }

    pub fn label(mut self, key: &'static str, value: &'static str) -> Self {
        self.labels.insert(key, value);
        self
    }
}

/// tests for searching (q style) for folders
#[test_context(TrustifyContext)]
#[rstest]
// with an empty (get all) query filter
#[case::no_filter("", [
    Item::new(&["A"]).label("product", "A"),
    Item::new(&["A", "A1"]),
    Item::new(&["A", "A1", "A1a"]),
    Item::new(&["A", "A1", "A1b"]),
    Item::new(&["A", "A2"]),
    Item::new(&["A", "A2", "A2a"]),
    Item::new(&["A", "A2", "A2b"]),
    Item::new(&["B"]).label("product", "B"),
    Item::new(&["B", "B1"]),
    Item::new(&["B", "B1", "B1a"]),
    Item::new(&["B", "B1", "B1b"]),
    Item::new(&["B", "B2"]),
    Item::new(&["B", "B2", "B2a"]),
    Item::new(&["B", "B2", "B2b"]),
])]
// search for name equals "A", root level folder
#[case::name_eq("name=A", [
    Item::new(&["A"]).label("product", "A"),
])]
// search for name equals "A1", level 2 folder
#[case::name_eq_l2("name=A1", [
    Item::new(&["A", "A1"]),
])]
// search for name contains "A"
#[case::name_like("name~A", [
    Item::new(&["A"]).label("product", "A"),
    Item::new(&["A", "A1"]),
    Item::new(&["A", "A1", "A1a"]),
    Item::new(&["A", "A1", "A1b"]),
    Item::new(&["A", "A2"]),
    Item::new(&["A", "A2","A2a"]),
    Item::new(&["A", "A2","A2b"]),
    Item::new(&["B", "B1", "B1a"]),
    Item::new(&["B", "B2", "B2a"]),
])]
#[test_log::test(actix_web::test)]
pub async fn list_groups(
    ctx: &TrustifyContext,
    #[case] q: String,
    #[case] expected_items: impl IntoIterator<Item = Item>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(app, ids, &q, expected_items).await?;

    Ok(())
}

/// A simple 3 level group setup
fn group_fixture_3_levels() -> Vec<Group> {
    vec![
        // level 1
        Group::new("A")
            .labels(("product", "A"))
            // level 2
            .add(
                Group::new("A1")
                    // level 3
                    .add("A1a")
                    .add("A1b"),
            )
            .add(
                Group::new("A2")
                    // level 3
                    .add("A2a")
                    .add("A2b"),
            ),
        Group::new("B")
            .labels(("product", "B"))
            // level 2
            .add(
                Group::new("B1")
                    // level 3
                    .add("B1a")
                    .add("B1b"),
            )
            .add(
                Group::new("B2")
                    // level 3
                    .add("B2a")
                    .add("B2b"),
            ),
    ]
}

/// Test query filtering by parent
#[test_context(TrustifyContext)]
#[rstest]
#[case::root_folder([], [
    Item::new(&["A"]).label("product", "A"),
    Item::new(&["B"]).label("product", "B"),
])]
#[case::level_2_folder(["A", "A1"], [
    Item::new(&["A", "A1", "A1a"]),
    Item::new(&["A", "A1", "A1b"]),
])]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_parent(
    ctx: &TrustifyContext,
    #[case] parent: impl IntoIterator<Item = &'static str>,
    #[case] expected: impl IntoIterator<Item = Item>,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    let parent: Vec<_> = parent.into_iter().collect();

    let parent = match parent.is_empty() {
        true => "\x00".to_string(),
        false => locate_id(&ids, parent),
    };

    run_list_test(app, ids, &format!("parent={parent}"), expected).await?;

    Ok(())
}

/// Test using an invalid parent ID
#[ignore = "Caused by the q implementation"]
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_invalid_parent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(app, ids, "parent=this-is-wrong", []).await?;

    Ok(())
}

/// Test using a missing parent ID
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
pub async fn list_groups_with_missing_parent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let ids = create_groups(&app, group_fixture_3_levels()).await?;

    run_list_test(app, ids, "parent=cc43ae38-d32d-49b8-9863-5e7f4409a133", []).await?;

    Ok(())
}

/// Run a "list SBOM groups" test
///
/// This takes in an ID-map from the [`create_groups`] function and expected items, which should
/// be the result of the query.
///
/// *Note:* This function might already panic when assertions fail.
async fn run_list_test(
    app: impl CallService,
    ids: HashMap<Vec<String>, String>,
    q: &str,
    expected_items: impl IntoIterator<Item = Item>,
) -> anyhow::Result<()> {
    let uri = "/api/v2/group/sbom?".to_string();
    let uri = format!("{uri}q={}&", urlencoding::encode(q));

    let request = TestRequest::get().uri(&uri);

    let response = app.call_service(request.to_request()).await;
    let status = response.status();
    log::info!("status: {status}");

    let body = to_bytes(response.into_body()).await.expect("must decode");
    log::info!("{:?}", str::from_utf8(&body));
    let body: Value = serde_json::from_slice(&body)?;

    assert!(status.is_success());

    log::info!("{body:?}");
    assert!(body["total"].is_number());
    assert!(body["items"].is_array());

    let response: PaginatedResults<GroupDetails> = serde_json::from_value(body)?;

    let expected_items = into_actual(expected_items, &ids);

    assert_eq!(response.total, expected_items.len() as u64);
    assert_eq!(response.items, expected_items);

    Ok(())
}

/// Locate an ID from the ID set
///
/// *Note:* This function will panic when IDs cannot be found.
fn locate_id(
    ids: &HashMap<Vec<String>, String>,
    id: impl IntoIterator<Item = impl ToString>,
) -> String {
    let path: Vec<String> = id.into_iter().map(|s| s.to_string()).collect();
    ids.get(&path)
        .unwrap_or_else(|| panic!("ID not found for path: {:?}", path))
        .clone()
}

/// Convert expected items into [`GroupDetails`] by resolving the IDs from the provided IDs set.
fn into_actual(
    expected: impl IntoIterator<Item = Item>,
    ids: &HashMap<Vec<String>, String>,
) -> Vec<GroupDetails> {
    expected
        .into_iter()
        .map(|item| {
            // Look up the ID for this item's path
            let id = locate_id(ids, item.id);

            // Determine the parent ID from the path
            let parent = if item.id.len() > 1 {
                Some(locate_id(ids, &item.id[..item.id.len() - 1]))
            } else {
                None
            };

            // Convert parents array to Vec<String> by looking up IDs for each path segment
            let parents = item.parents.map(|parent_segments| {
                parent_segments
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        // Build the cumulative path up to this segment
                        locate_id(ids, &parent_segments[..=i])
                    })
                    .collect()
            });

            GroupDetails {
                group: crate::sbom_group::model::Group {
                    id,
                    parent,
                    name: item.name.to_string(),
                    labels: item.labels.into(),
                },
                number_of_groups: item.total_groups,
                number_of_sboms: item.total_sboms,
                parents,
            }
        })
        .collect()
}

#[derive()]
struct Group {
    name: String,
    labels: Labels,
    children: Vec<Group>,
}

impl Group {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            labels: Default::default(),
            children: Default::default(),
        }
    }

    pub fn add(mut self, group: impl Into<Group>) -> Self {
        self.children.push(group.into());
        self
    }

    /// Replace labels with current
    pub fn labels(mut self, labels: impl Into<Labels>) -> Self {
        self.labels = labels.into();
        self
    }
}

impl From<&str> for Group {
    fn from(value: &str) -> Self {
        Self {
            name: value.to_string(),
            children: vec![],
            labels: Labels::default(),
        }
    }
}

/// Create groups, with the provided structure, returning a map of name hierarchy to the ID.
async fn create_groups(
    app: &impl CallService,
    groups: Vec<Group>,
) -> anyhow::Result<HashMap<Vec<String>, String>> {
    let mut result = HashMap::new();

    for group in groups {
        create_group_recursive(app, group, None, vec![], &mut result).await?;
    }

    Ok(result)
}

/// Helper function to recursively create a group and its children
async fn create_group_recursive(
    app: &impl CallService,
    group: Group,
    parent_id: Option<&str>,
    mut path: Vec<String>,
    result: &mut HashMap<Vec<String>, String>,
) -> anyhow::Result<()> {
    // Add current group name to path
    path.push(group.name.clone());

    // Create the group
    let created: GroupResponse = Create::new(&group.name)
        .parent(parent_id)
        .labels(group.labels)
        .execute(app)
        .await?;

    // Store in result map (path -> ID)
    result.insert(path.clone(), created.id.clone());

    // Recursively create children
    for child in group.children {
        Box::pin(async {
            create_group_recursive(app, child, Some(&created.id), path.clone(), result).await
        })
        .await?;
    }

    Ok(())
}

/// Helper struct for SBOM assignment response
struct AssignmentResponse {
    group_ids: Vec<String>,
    etag: String,
}

/// Helper to read SBOM group assignments
async fn read_assignments(
    app: &impl CallService,
    sbom_id: &str,
) -> anyhow::Result<AssignmentResponse> {
    let response = app
        .call_service(
            TestRequest::get()
                .uri(&format!("/api/v2/group/sbom-assignment/{}", sbom_id))
                .to_request(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers().clone();
    let group_ids: Vec<String> = actix_web::test::read_body_json(response).await;

    Ok(AssignmentResponse {
        group_ids,
        etag: headers
            .get(&http::header::ETAG)
            .expect("must have etag header")
            .to_str()
            .expect("etag must be valid string")
            .to_string(),
    })
}

struct UpdateAssignments {
    sbom_id: String,
    group_ids: Vec<String>,
    if_match_type: IfMatchType,
    etag: Option<String>,
    expected_status: StatusCode,
}

impl UpdateAssignments {
    pub fn new(sbom_id: impl Into<String>) -> Self {
        Self {
            sbom_id: sbom_id.into(),
            group_ids: vec![],
            if_match_type: IfMatchType::Correct,
            etag: None,
            expected_status: StatusCode::NO_CONTENT,
        }
    }

    pub fn etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    pub fn group_ids(mut self, group_ids: Vec<String>) -> Self {
        self.group_ids = group_ids;
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
        let initial_etag = self.etag.clone();

        let request = TestRequest::put()
            .uri(&format!("/api/v2/group/sbom-assignment/{}", &self.sbom_id))
            .set_json(&self.group_ids);

        let request = match self.etag {
            Some(etag) => add_if_match(request, self.if_match_type, &etag),
            None => request,
        };

        let response = app.call_service(request.to_request()).await;
        assert_eq!(response.status(), self.expected_status);

        // Verify etag behavior based on success/failure
        let assignments_after = read_assignments(app, &self.sbom_id).await?;

        if let Some(initial_etag) = initial_etag {
            if self.expected_status.is_success() {
                assert_ne!(
                    initial_etag, assignments_after.etag,
                    "etag should have changed after successful update"
                );
            } else {
                assert_eq!(
                    initial_etag, assignments_after.etag,
                    "etag should not have changed after failed update"
                );
            }
        }

        Ok(())
    }
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn sbom_group_assignments(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Create two groups
    let group1: GroupResponse = Create::new("Group 1").execute(&app).await?;
    let group2: GroupResponse = Create::new("Group 2").execute(&app).await?;

    // Ingest an SBOM
    let sbom_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom_result.id.to_string();

    // Read initial assignments (should be empty)
    let assignments = read_assignments(&app, &sbom_id).await?;
    assert_eq!(assignments.group_ids.len(), 0);

    // Update assignments to add both groups
    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![group1.id.clone(), group2.id.clone()])
        .execute(&app)
        .await?;

    // Read assignments again (should have both groups)
    let assignments = read_assignments(&app, &sbom_id).await?;
    assert_eq!(assignments.group_ids.len(), 2);
    assert!(assignments.group_ids.contains(&group1.id));
    assert!(assignments.group_ids.contains(&group2.id));

    // Update to remove one group
    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![group1.id.clone()])
        .execute(&app)
        .await?;

    // Verify only one group remains
    let assignments = read_assignments(&app, &sbom_id).await?;
    assert_eq!(assignments.group_ids.len(), 1);
    assert_eq!(assignments.group_ids[0], group1.id);

    // Update to empty list
    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![])
        .execute(&app)
        .await?;

    // Verify assignments are empty
    let assignments = read_assignments(&app, &sbom_id).await?;
    assert_eq!(assignments.group_ids.len(), 0);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn sbom_group_assignments_not_found(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Test invalid SBOM ID (404)
    let response = app
        .call_service(
            TestRequest::get()
                .uri("/api/v2/group/sbom-assignment/00000000-0000-0000-0000-000000000000")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn sbom_group_assignments_invalid_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Ingest an SBOM
    let sbom_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom_result.id.to_string();

    // Test invalid group ID format (400)
    UpdateAssignments::new(&sbom_id)
        .group_ids(vec!["not-a-valid-uuid".to_string()])
        .expect_status(StatusCode::BAD_REQUEST)
        .execute(&app)
        .await?;

    // Test non-existent group ID (400)
    UpdateAssignments::new(&sbom_id)
        .group_ids(vec!["00000000-0000-0000-0000-000000000000".to_string()])
        .expect_status(StatusCode::BAD_REQUEST)
        .execute(&app)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case::wildcard(IfMatchType::Wildcard, StatusCode::NO_CONTENT)]
#[case::correct_revision(IfMatchType::Correct, StatusCode::NO_CONTENT)]
#[case::wrong_revision(IfMatchType::Wrong, StatusCode::PRECONDITION_FAILED)]
#[test_log::test(actix_web::test)]
async fn sbom_group_assignments_if_match(
    ctx: &TrustifyContext,
    #[case] if_match_type: IfMatchType,
    #[case] expected_status: StatusCode,
) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Ingest an SBOM
    let sbom_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom_result.id.to_string();

    let assignments = read_assignments(&app, &sbom_id).await?;

    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![])
        .if_match(if_match_type)
        .expect_status(expected_status)
        .execute(&app)
        .await?;

    Ok(())
}
