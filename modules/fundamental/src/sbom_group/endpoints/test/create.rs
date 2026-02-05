use super::{IfMatchType, Update, get_group_helper};
use crate::{
    sbom_group::endpoints::test::{Create, GroupResponse, add_if_match},
    test::caller,
};
use actix_web::{http::StatusCode, test::TestRequest};
use rstest::rstest;
use serde_json::Value;
use test_context::test_context;
use trustify_entity::labels::Labels;
use trustify_test_context::{TrustifyContext, call::CallService};

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
