use actix_http::StatusCode;
use actix_web::test::TestRequest;
use sea_orm::EntityTrait;
use serde_json::Value;
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::id::Id;
use trustify_entity::source_document;
use trustify_test_context::{TrustifyContext, call::CallService};

use crate::test::caller;

/// Verify that a SBOM exists by checking the GET endpoint returns OK
async fn verify_sbom_exists(
    app: &impl CallService,
    sbom_id: &Id,
    expected_status: StatusCode,
) -> Result<(), anyhow::Error> {
    let req = TestRequest::get()
        .uri(&format!("/api/v2/sbom/{}", sbom_id))
        .to_request();
    let resp = app.call_service(req).await;
    assert_eq!(resp.status(), expected_status);
    Ok(())
}

/// Ingest test SBOMs and update their ingested date to be older than specified days
async fn ingest_test_sboms_with_old_date(
    ctx: &TrustifyContext,
    days_old: i64,
) -> Result<(Id, Id), anyhow::Error> {
    // Ingest test SBOMs
    let result_spdx = ctx
        .ingest_document("spdx/OCP-TOOLS-4.11-RHEL-8.json")
        .await?;
    let result_cyclonedx = ctx
        .ingest_document("cyclonedx/application.cdx.json")
        .await?;

    // Manually update the ingested date to be older than specified days for testing
    let old_date = OffsetDateTime::now_utc() - time::Duration::days(days_old);
    source_document::Entity::update_many()
        .col_expr(source_document::Column::Ingested, old_date.into())
        .exec(&ctx.db)
        .await?;

    Ok((result_spdx.id, result_cyclonedx.id))
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_prune_sboms_dry_run(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Ingest test SBOMs with old date (100 days ago)
    let (result_spdx, result_cyclonedx) = ingest_test_sboms_with_old_date(ctx, 100).await?;

    let app = caller(ctx).await?;

    // Create test request with dry-run=true
    let req = TestRequest::post()
        .uri("/api/v2/admin/sbom/prune?ingested=90&dry-run=true&batch-size=10&max-concurrent=5")
        .to_request();

    // Call the endpoint
    let response: Value = app.call_and_read_body_json(req).await;

    // Verify response is an object
    assert!(
        response.is_object(),
        "Expected response to be an object, got: {:?}",
        response
    );

    // Verify successful_total equals 2
    let successful_total = response
        .get("successful_total")
        .and_then(|v| v.as_u64())
        .expect("Response should have successful_total field");
    assert_eq!(
        successful_total, 2,
        "Expected successful_total to be 2, got: {}",
        successful_total
    );

    // Verify total equals 2
    let total = response
        .get("total")
        .and_then(|v| v.as_u64())
        .expect("Response should have total field");
    assert_eq!(total, 2, "Expected total to be 2, got: {}", total);

    // Verify failed_total equals 0 (dry run mode)
    let failed_total = response
        .get("failed_total")
        .and_then(|v| v.as_u64())
        .expect("Response should have failed_total field");
    assert_eq!(
        failed_total, 0,
        "Expected failed_total to be 0 in dry run mode, got: {}",
        failed_total
    );

    // Verify successful_pruned array has 2 items
    let successful_pruned = response
        .get("successful_pruned")
        .and_then(|v| v.as_array())
        .expect("Response should have successful_pruned array");
    assert_eq!(
        successful_pruned.len(),
        2,
        "Expected successful_pruned to have 2 items, got: {}",
        successful_pruned.len()
    );

    // Verify SBOMs still exist (dry run)
    verify_sbom_exists(&app, &result_spdx, StatusCode::OK).await?;
    verify_sbom_exists(&app, &result_cyclonedx, StatusCode::OK).await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_prune_sboms_actual_deletion(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Ingest test SBOMs with old date (100 days ago)
    let (result_spdx, result_cyclonedx) = ingest_test_sboms_with_old_date(ctx, 100).await?;

    let app = caller(ctx).await?;

    // Create test request with dry-run=false
    let req = TestRequest::post()
        .uri("/api/v2/admin/sbom/prune?ingested=90&dry-run=false&batch-size=10&max-concurrent=5")
        .to_request();

    // Call the endpoint
    let response: Value = app.call_and_read_body_json(req).await;

    // Verify response is an object
    assert!(
        response.is_object(),
        "Expected response to be an object, got: {:?}",
        response
    );

    // Verify successful_total equals 2
    let successful_total = response
        .get("successful_total")
        .and_then(|v| v.as_u64())
        .expect("Response should have successful_total field");
    assert_eq!(
        successful_total, 2,
        "Expected successful_total to be 2, got: {}",
        successful_total
    );

    // Verify total equals 2
    let total = response
        .get("total")
        .and_then(|v| v.as_u64())
        .expect("Response should have total field");
    assert_eq!(total, 2, "Expected total to be 2, got: {}", total);

    // Verify failed_total equals 0 (actual deletion mode)
    let failed_total = response
        .get("failed_total")
        .and_then(|v| v.as_u64())
        .expect("Response should have failed_total field");
    assert_eq!(
        failed_total, 0,
        "Expected failed_total to be 0 in actual deletion mode, got: {}",
        failed_total
    );

    // Verify successful_pruned array has 2 items
    let successful_pruned = response
        .get("successful_pruned")
        .and_then(|v| v.as_array())
        .expect("Response should have successful_pruned array");
    assert_eq!(
        successful_pruned.len(),
        2,
        "Expected successful_pruned to have 2 items, got: {}",
        successful_pruned.len()
    );

    // Verify SBOMs no longer exist (actual deletion)
    verify_sbom_exists(&app, &result_spdx, StatusCode::NOT_FOUND).await?;
    verify_sbom_exists(&app, &result_cyclonedx, StatusCode::NOT_FOUND).await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_prune_sboms_no_matches(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Ingest test SBOMs with old date (0 days ago)
    let (result_spdx, result_cyclonedx) = ingest_test_sboms_with_old_date(ctx, 0).await?;

    let app = caller(ctx).await?;

    // Create test request with dry-run=false
    let req = TestRequest::post()
        .uri("/api/v2/admin/sbom/prune?ingested=90&dry-run=false&batch-size=10&max-concurrent=5")
        .to_request();

    // Call the endpoint
    let response: Value = app.call_and_read_body_json(req).await;

    // Verify response is an object
    assert!(
        response.is_object(),
        "Expected response to be an object, got: {:?}",
        response
    );

    // Verify successful_total equals 0 (no matches)
    let successful_total = response
        .get("successful_total")
        .and_then(|v| v.as_u64())
        .expect("Response should have successful_total field");
    assert_eq!(
        successful_total, 0,
        "Expected successful_total to be 0 when no matches, got: {}",
        successful_total
    );

    // Verify total equals 0
    let total = response
        .get("total")
        .and_then(|v| v.as_u64())
        .expect("Response should have total field");
    assert_eq!(
        total, 0,
        "Expected total to be 0 when no matches, got: {}",
        total
    );

    // Verify failed_total equals 0 (no matches)
    let failed_total = response
        .get("failed_total")
        .and_then(|v| v.as_u64())
        .expect("Response should have failed_total field");
    assert_eq!(
        failed_total, 0,
        "Expected failed_total to be 0 when no matches, got: {}",
        failed_total
    );

    // Verify successful_pruned array is empty
    let successful_pruned = response
        .get("successful_pruned")
        .and_then(|v| v.as_array())
        .expect("Response should have successful_pruned array");
    assert_eq!(
        successful_pruned.len(),
        0,
        "Expected successful_pruned to be empty when no matches, got: {}",
        successful_pruned.len()
    );

    // Verify SBOMs still exist (no deletion)
    verify_sbom_exists(&app, &result_spdx, StatusCode::OK).await?;
    verify_sbom_exists(&app, &result_cyclonedx, StatusCode::OK).await?;
    Ok(())
}

// #[test_context(TrustifyContext)]
// #[test(actix_web::test)]
// async fn test_prune_sboms_error_field_validation(
//     ctx: &TrustifyContext,
// ) -> Result<(), anyhow::Error> {
//     // Ingest test SBOMs with old date (100 days ago)
//     let (_result_spdx, _result_cyclonedx) = ingest_test_sboms_with_old_date(ctx, 100).await?;

//     let app = caller(ctx).await?;

//     // Create test request with dry-run=false
//     let req = TestRequest::post()
//         .uri("/api/v2/admin/sbom/prune?ingested=90&dry-run=false&batch-size=10&max-concurrent=5")
//         .to_request();

//     // Call the endpoint
//     let response: Value = app.call_and_read_body_json(req).await;

//     // Verify response is an object
//     assert!(
//         response.is_object(),
//         "Expected response to be an object, got: {:?}",
//         response
//     );

//     // Verify successful_pruned items have error field set to null
//     let successful_pruned = response
//         .get("successful_pruned")
//         .and_then(|v| v.as_array())
//         .expect("Response should have successful_pruned array");

//     for (index, sbom) in successful_pruned.iter().enumerate() {
//         let error = sbom
//             .get("error")
//             .expect("Each SBOM should have error field");
//         assert!(
//             error.is_null(),
//             "Successful SBOM at index {} should have null error field, got: {:?}",
//             index,
//             error
//         );
//     }

//     // Verify failed_pruned items have error field set to a string (if any failures)
//     let failed_pruned = response
//         .get("failed_pruned")
//         .and_then(|v| v.as_array())
//         .expect("Response should have failed_pruned array");

//     for (index, sbom) in failed_pruned.iter().enumerate() {
//         let error = sbom
//             .get("error")
//             .expect("Each SBOM should have error field");
//         assert!(
//             error.is_string(),
//             "Failed SBOM at index {} should have string error field, got: {:?}",
//             index,
//             error
//         );
//         let error_msg = error.as_str().expect("Error should be a string");
//         assert!(
//             !error_msg.is_empty(),
//             "Failed SBOM at index {} should have non-empty error message",
//             index
//         );
//     }

//     Ok(())
// }
