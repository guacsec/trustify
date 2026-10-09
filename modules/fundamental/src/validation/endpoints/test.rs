use crate::{test::caller, validation::model::ValidationReportSummary};
use actix_web::test::TestRequest;
use sea_orm::{ActiveValue::Set, EntityTrait};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::id::Id;
use trustify_common::model::PaginatedResults;
use trustify_entity::validation_report;
use trustify_module_ingestor::service::validation::store::digest_for_document;
use trustify_test_context::{TrustifyContext, call::CallService};
use uuid::Uuid;

/// Insert a report directly: the endpoints read what ingestion recorded, and
/// the recording itself is covered by the ingestor's own tests.
async fn record(
    ctx: &TrustifyContext,
    document_sha256: &str,
    validator: &str,
    blocked: bool,
) -> Result<(), anyhow::Error> {
    validation_report::Entity::insert(validation_report::ActiveModel {
        id: Set(Uuid::now_v7()),
        document_sha256: Set(document_sha256.to_string()),
        validator: Set(validator.to_string()),
        mode: Set(validation_report::Mode::Verify),
        outcome: Set(validation_report::Outcome::Failed),
        blocked: Set(blocked),
        max_severity: Set(Some(validation_report::Severity::Error)),
        finding_count: Set(1),
        findings: Set(serde_json::json!([{ "severity": "error", "message": "nope" }])),
        truncated: Set(false),
        content_hash: Set(format!("hash-{validator}")),
        config_fingerprint: Set("fingerprint".to_string()),
        ingest_source: Set(validation_report::IngestSource::Api),
        importer_name: Set(None),
        created_at: Set(OffsetDateTime::now_utc()),
    })
    .exec(&ctx.db)
    .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_validation_reports(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    record(ctx, &"a".repeat(64), "scheck", false).await?;
    record(ctx, &"b".repeat(64), "csaf-spec", true).await?;

    let app = caller(ctx).await?;
    let request = TestRequest::get()
        .uri("/api/v3/validation?total=true")
        .to_request();
    let response: PaginatedResults<ValidationReportSummary> =
        app.call_and_read_body_json(request).await;

    assert_eq!(response.total, Some(2));

    // A rejected document is only visible here: it has no SBOM or advisory to
    // be listed under.
    let request = TestRequest::get()
        .uri("/api/v3/validation?q=blocked%3Dtrue")
        .to_request();
    let response: PaginatedResults<ValidationReportSummary> =
        app.call_and_read_body_json(request).await;

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0].validator, "csaf-spec");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_validation_reports_by_digest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digest = "c".repeat(64);
    record(ctx, &digest, "scheck", false).await?;

    let app = caller(ctx).await?;
    let request = TestRequest::get()
        .uri(&format!("/api/v3/validation/sha256%3A{digest}"))
        .to_request();
    let response: Vec<ValidationReportSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response[0].document_sha256, digest);
    assert!(!response[0].blocked);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_validation_reports_by_sbom_id(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let digest = digest_for_document(&ctx.db, Id::Uuid(Uuid::parse_str(&result.id)?))
        .await?
        .expect("ingested document has a source document");

    record(ctx, &digest, "scheck", false).await?;

    let app = caller(ctx).await?;
    let request = TestRequest::get()
        .uri(&format!("/api/v3/validation/urn:uuid:{}", result.id))
        .to_request();
    let response: Vec<ValidationReportSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response[0].document_sha256, digest);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_validation_reports_by_name(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?;
    let digest = digest_for_document(&ctx.db, Id::Uuid(Uuid::parse_str(&result.id)?))
        .await?
        .expect("ingested document has a source document");

    record(ctx, &digest, "scheck", false).await?;
    record(ctx, &"d".repeat(64), "scheck", false).await?;

    let app = caller(ctx).await?;
    let request = TestRequest::get()
        .uri("/api/v3/validation?name=zookeeper")
        .to_request();
    let response: PaginatedResults<ValidationReportSummary> =
        app.call_and_read_body_json(request).await;

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0].document_sha256, digest);

    Ok(())
}
