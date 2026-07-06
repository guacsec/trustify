use crate::{
    common::test::{
        Create, Group, GroupResponse, IfMatchType, PatchAssignments, UpdateAssignments,
        create_groups, locate_id, locate_ids, read_assignments,
    },
    sbom_group::model::BulkAssignmentRequest,
    test::caller,
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use rstest::rstest;
use serde_json::json;
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
                .uri("/api/v3/group/sbom-assignment/00000000-0000-0000-0000-000000000000")
                .to_request(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case::invalid_format("not-a-valid-uuid", StatusCode::BAD_REQUEST)]
#[case::nonexistent("00000000-0000-0000-0000-000000000000", StatusCode::BAD_REQUEST)]
#[test_log::test(actix_web::test)]
async fn sbom_group_assignments_invalid_group(
    ctx: &TrustifyContext,
    #[case] group_id: &str,
    #[case] expected_status: StatusCode,
) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let sbom_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom_result.id.to_string();

    UpdateAssignments::new(&sbom_id)
        .group_ids(vec![group_id.to_string()])
        .expect_status(expected_status)
        .execute(&app)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn sbom_group_assignments_duplicate_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group: GroupResponse = Create::new("Group 1").execute(&app).await?;

    let sbom_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom_result.id.to_string();

    let assignments = read_assignments(&app, &sbom_id).await?;

    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![group.id.clone(), group.id.clone()])
        .execute(&app)
        .await?;

    let assignments = read_assignments(&app, &sbom_id).await?;
    assert_eq!(assignments.group_ids.len(), 1);
    assert_eq!(assignments.group_ids[0], group.id);

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

async fn assert_assigned_groups(
    app: &impl CallService,
    sbom_id: &str,
    expected: &[&str],
) -> anyhow::Result<()> {
    let mut actual = read_assignments(app, sbom_id).await?.group_ids;
    actual.sort();
    let mut expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(actual, expected);
    Ok(())
}

async fn call_assign(
    app: &impl CallService,
    sbom_id: &str,
    body: impl serde::Serialize,
) -> StatusCode {
    app.call_service(
        TestRequest::put()
            .uri(&format!("/api/v3/group/sbom-assignment/{sbom_id}"))
            .set_json(body)
            .to_request(),
    )
    .await
    .status()
}

async fn call_bulk_assign(app: &impl CallService, body: impl serde::Serialize) -> StatusCode {
    app.call_service(
        TestRequest::put()
            .uri("/api/v3/group/sbom-assignment")
            .set_json(body)
            .to_request(),
    )
    .await
    .status()
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group1: GroupResponse = Create::new("Group 1").execute(&app).await?;
    let group2: GroupResponse = Create::new("Group 2").execute(&app).await?;

    let sbom1 = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom2 = ctx.ingest_document("spdx/simple.json").await?;
    let sbom1_id = sbom1.id.to_string();
    let sbom2_id = sbom2.id.to_string();

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec![sbom1_id.clone(), sbom2_id.clone()],
            group_ids: vec![group1.id.clone(), group2.id.clone()],
        },
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_assigned_groups(&app, &sbom1_id, &[&group1.id, &group2.id]).await?;
    assert_assigned_groups(&app, &sbom2_id, &[&group1.id, &group2.id]).await?;

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec![sbom1_id.clone(), sbom2_id.clone()],
            group_ids: vec![group1.id.clone()],
        },
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_assigned_groups(&app, &sbom1_id, &[&group1.id]).await?;
    assert_assigned_groups(&app, &sbom2_id, &[&group1.id]).await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments_invalid_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let status = call_bulk_assign(
        &app,
        json!({
            "sbom_ids": ["not-a-valid-uuid"],
            "group_ids": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments_invalid_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec![sbom.id.to_string()],
            group_ids: vec!["not-a-valid-uuid".to_string()],
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments_empty(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec![],
            group_ids: vec![],
        },
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments_nonexistent_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec!["00000000-0000-0000-0000-000000000000".to_string()],
            group_ids: vec![],
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments_duplicate_sbom(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group: GroupResponse = Create::new("Group 1").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec![sbom_id.clone(), sbom_id.clone()],
            group_ids: vec![group.id.clone()],
        },
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_assigned_groups(&app, &sbom_id, &[&group.id]).await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn bulk_sbom_group_assignments_duplicate_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group: GroupResponse = Create::new("Group 1").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    let status = call_bulk_assign(
        &app,
        BulkAssignmentRequest {
            sbom_ids: vec![sbom_id.clone()],
            group_ids: vec![group.id.clone(), group.id.clone()],
        },
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_assigned_groups(&app, &sbom_id, &[&group.id]).await?;

    Ok(())
}

/// Verify that concurrent SBOM group assignments preserve replace semantics.
///
/// `update_assignments` replaces ALL group assignments for an SBOM, so after
/// two requests -- whether sequential or concurrent -- exactly one group must
/// remain. The sequential case always keeps the last writer's group; the
/// concurrent case may keep either, but never both and never none.
#[test_context(TrustifyContext)]
#[rstest]
#[case::sequential(false, &["Group 2"])]
#[case::parallel(true, &["Group 1", "Group 2"])]
#[test_log::test(actix_web::test)]
async fn concurrent_sbom_group_assignment_race(
    ctx: &TrustifyContext,
    #[case] parallel: bool,
    #[case] in_expected: &[&str],
) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    // Given: an SBOM and two groups
    let groups = create_groups(&app, vec![Group::new("Group 1"), Group::new("Group 2")]).await?;
    let group1_id = locate_id(&groups, ["Group 1"]);
    let group2_id = locate_id(&groups, ["Group 2"]);
    let in_expected = locate_ids(&groups, in_expected.iter().map(|name| [*name]));

    let sbom_result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    // When: two requests each assign the SBOM to a different group
    let (status1, status2) = if parallel {
        tokio::join!(
            call_assign(&app, &sbom_result.id, vec![&group1_id]),
            call_assign(&app, &sbom_result.id, vec![&group2_id]),
        )
    } else {
        (
            call_assign(&app, &sbom_result.id, vec![&group1_id]).await,
            call_assign(&app, &sbom_result.id, vec![&group2_id]).await,
        )
    };

    assert_eq!(status1, StatusCode::NO_CONTENT);
    assert_eq!(status2, StatusCode::NO_CONTENT);

    // Then: exactly one group must remain (replace semantics)
    let actual = read_assignments(&app, &sbom_result.id).await?.group_ids;
    assert_eq!(actual.len(), 1, "exactly one group must be present");
    assert!(in_expected.contains(&actual[0]));

    Ok(())
}

// --- PATCH assignment tests ---

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_add(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group1: GroupResponse = Create::new("Group 1").execute(&app).await?;
    let group2: GroupResponse = Create::new("Group 2").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    PatchAssignments::new(vec![sbom_id.clone()])
        .add_groups(vec![group1.id.clone(), group2.id.clone()])
        .execute(&app)
        .await?;

    assert_assigned_groups(&app, &sbom_id, &[&group1.id, &group2.id]).await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_remove(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group1: GroupResponse = Create::new("Group 1").execute(&app).await?;
    let group2: GroupResponse = Create::new("Group 2").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    // Set up initial assignments via PUT
    let assignments = read_assignments(&app, &sbom_id).await?;
    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![group1.id.clone(), group2.id.clone()])
        .execute(&app)
        .await?;

    // Remove one group via PATCH
    PatchAssignments::new(vec![sbom_id.clone()])
        .remove_groups(vec![group1.id.clone()])
        .execute(&app)
        .await?;

    assert_assigned_groups(&app, &sbom_id, &[&group2.id]).await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_add_and_remove(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group1: GroupResponse = Create::new("Group 1").execute(&app).await?;
    let group2: GroupResponse = Create::new("Group 2").execute(&app).await?;
    let group3: GroupResponse = Create::new("Group 3").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    // Set up initial assignment to group1 and group2
    let assignments = read_assignments(&app, &sbom_id).await?;
    UpdateAssignments::new(&sbom_id)
        .etag(&assignments.etag)
        .group_ids(vec![group1.id.clone(), group2.id.clone()])
        .execute(&app)
        .await?;

    // PATCH: add group3, remove group1
    PatchAssignments::new(vec![sbom_id.clone()])
        .add_groups(vec![group3.id.clone()])
        .remove_groups(vec![group1.id.clone()])
        .execute(&app)
        .await?;

    assert_assigned_groups(&app, &sbom_id, &[&group2.id, &group3.id]).await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_idempotent(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group: GroupResponse = Create::new("Group 1").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    // Add group
    PatchAssignments::new(vec![sbom_id.clone()])
        .add_groups(vec![group.id.clone()])
        .execute(&app)
        .await?;

    // Add same group again (idempotent, should not error)
    PatchAssignments::new(vec![sbom_id.clone()])
        .add_groups(vec![group.id.clone()])
        .execute(&app)
        .await?;

    assert_assigned_groups(&app, &sbom_id, &[&group.id]).await?;

    // Remove a group that is not assigned (idempotent, should not error)
    PatchAssignments::new(vec![sbom_id.clone()])
        .remove_groups(vec!["00000000-0000-0000-0000-000000000099".to_string()])
        .execute(&app)
        .await?;

    assert_assigned_groups(&app, &sbom_id, &[&group.id]).await?;

    Ok(())
}

/// Core regression test for TC-5036: adding Group B must preserve existing Group A.
#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_preserves_existing(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let group_a: GroupResponse = Create::new("Group A").execute(&app).await?;
    let group_b: GroupResponse = Create::new("Group B").execute(&app).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let sbom_id = sbom.id.to_string();

    // Assign to Group A
    PatchAssignments::new(vec![sbom_id.clone()])
        .add_groups(vec![group_a.id.clone()])
        .execute(&app)
        .await?;

    // Now add to Group B -- Group A must be preserved
    PatchAssignments::new(vec![sbom_id.clone()])
        .add_groups(vec![group_b.id.clone()])
        .execute(&app)
        .await?;

    assert_assigned_groups(&app, &sbom_id, &[&group_a.id, &group_b.id]).await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[rstest]
#[case::nonexistent_sbom(
    vec!["00000000-0000-0000-0000-000000000000"],
    vec![],
    StatusCode::NOT_FOUND
)]
#[case::invalid_sbom_uuid(
    vec!["not-a-valid-uuid"],
    vec![],
    StatusCode::NOT_FOUND
)]
#[case::empty_sbom_ids(
    vec![],
    vec![],
    StatusCode::NO_CONTENT
)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_errors(
    ctx: &TrustifyContext,
    #[case] sbom_ids: Vec<&str>,
    #[case] add_groups: Vec<&str>,
    #[case] expected_status: StatusCode,
) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    PatchAssignments::new(sbom_ids.into_iter().map(String::from).collect())
        .add_groups(add_groups.into_iter().map(String::from).collect())
        .expect_status(expected_status)
        .execute(&app)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn patch_sbom_group_assignments_invalid_group(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let sbom = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;

    PatchAssignments::new(vec![sbom.id.to_string()])
        .add_groups(vec!["00000000-0000-0000-0000-000000000099".to_string()])
        .expect_status(StatusCode::BAD_REQUEST)
        .execute(&app)
        .await?;

    Ok(())
}
