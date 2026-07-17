#[cfg(test)]
mod test;

use crate::service::{CorrelationService, hydrate};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadSbom, authorizer::Require, utoipa::AuthResponse};
use trustify_common::db;
use utoipa_actix_web::service_config::ServiceConfig;

/// Registers in-memory correlation endpoints (replaces the SQL-based v3a path).
pub fn configure(config: &mut ServiceConfig, db: db::ReadOnly, correlation: CorrelationService) {
    config
        .app_data(web::Data::new(correlation))
        .app_data(web::Data::new(db))
        .service(get_sbom_advisories)
        .service(correlation_status);
}

#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationSbomAdvisories",
    params(
        ("id" = Uuid, Path, description = "SBOM ID"),
    ),
    responses(
        AuthResponse,
        (status = 200, description = "Advisories affecting this SBOM"),
        (status = 404, description = "SBOM not found"),
        (status = 503, description = "Correlation service not ready"),
    ),
)]
#[get("/v3/sbom/{id}/advisory")]
/// Find advisories affecting an SBOM using in-memory correlation.
async fn get_sbom_advisories(
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<uuid::Uuid>,
    _user: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let matches = service.correlate_sbom(*id)?;
    let statuses = service.status_slugs();
    let txn = db.begin().await?;
    let advisories = hydrate::hydrate_matches(matches, &statuses, &txn).await?;

    Ok(HttpResponse::Ok().json(advisories))
}

#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationStatus",
    responses(
        AuthResponse,
        (status = 200, description = "Correlation service status"),
    ),
)]
#[get("/v3/correlation/status")]
/// Get the status of the correlation service.
async fn correlation_status(
    service: web::Data<CorrelationService>,
    _user: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let state = service.state();
    let advisory_count = state.advisory_index.by_purl.len();
    let sbom_count = state.sbom_index.by_sbom.len();
    let catalog_count = state.sbom_index.catalog.len();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "advisory_purl_keys": advisory_count,
        "sboms": sbom_count,
        "catalog_entries": catalog_count,
    })))
}
