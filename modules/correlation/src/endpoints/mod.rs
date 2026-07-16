#[cfg(test)]
mod test;

use crate::service::CorrelationService;
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadSbom, authorizer::Require, utoipa::AuthResponse};
use trustify_common::db;
use utoipa_actix_web::service_config::ServiceConfig;

/// Registers v4 correlation endpoints.
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
#[get("/v4/sbom/{id}/advisory")]
/// Find advisories affecting an SBOM using in-memory correlation.
async fn get_sbom_advisories(
    service: web::Data<CorrelationService>,
    id: web::Path<uuid::Uuid>,
    _user: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let matches = service.correlate_sbom(*id)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "matches": matches.len(),
    })))
}

#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationStatus",
    responses(
        AuthResponse,
        (status = 200, description = "Correlation service status"),
    ),
)]
#[get("/v4/correlation/status")]
/// Get the status of the correlation service.
async fn correlation_status(
    service: web::Data<CorrelationService>,
    _user: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let state = service.state();
    let advisory_count = state.advisory_index.by_base_purl.len();
    let sbom_count = state.sbom_index.by_sbom.len();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "advisory_base_purls": advisory_count,
        "sboms": sbom_count,
    })))
}
