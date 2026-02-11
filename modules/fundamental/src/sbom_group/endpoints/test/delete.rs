use super::get_group_helper;
use crate::{
    common::test::{Create, GroupResponse},
    test::caller,
};
use actix_http::StatusCode;
use actix_web::{http, test::TestRequest};
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

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
