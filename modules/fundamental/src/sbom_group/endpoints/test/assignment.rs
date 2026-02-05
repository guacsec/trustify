use crate::{
    sbom_group::endpoints::test::{
        Create, GroupResponse, IfMatchType, UpdateAssignments, read_assignments,
    },
    test::caller,
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use rstest::rstest;
use test_context::test_context;
use trustify_test_context::{TrustifyContext, call::CallService};

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
