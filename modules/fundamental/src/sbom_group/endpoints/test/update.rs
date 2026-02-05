use super::{IfMatchType, Update};
use crate::{
    sbom_group::endpoints::test::{Create, GroupResponse, get_group_helper},
    test::caller,
};
use actix_http::StatusCode;
use rstest::rstest;
use serde_json::json;
use test_context::test_context;
use trustify_entity::labels::Labels;
use trustify_test_context::TrustifyContext;

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
