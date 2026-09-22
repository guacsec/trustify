use crate::{error::Error, model::CorrelationResult, service::CorrelationService};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_common::db;
use uuid::Uuid;

#[cfg(test)]
mod test;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_ro: db::ReadOnly,
) {
    let service = CorrelationService;
    config
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(service))
        .service(get_sbom_correlation);
}

/// Get correlation verdicts for an SBOM.
#[utoipa::path(
    tag = "correlation",
    operation_id = "getSbomCorrelation",
    params(
        ("id" = Uuid, Path, description = "SBOM ID"),
    ),
    responses(
        (status = 200, description = "Correlation verdicts for the SBOM", body = CorrelationResult),
    ),
)]
#[get("/v3/correlation/sbom/{id}")]
async fn get_sbom_correlation(
    sbom_id: web::Path<Uuid>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = service.correlate_sbom(*sbom_id, &tx).await?;
    Ok(HttpResponse::Ok().json(result))
}
