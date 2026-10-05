use crate::{
    error::Error,
    model::{CorrelationResult, IdentifierKind, IdentifierRef, QueryResult},
    service::CorrelationService,
};
use actix_web::{HttpResponse, Responder, get, web};
use serde::Deserialize;
use trustify_common::db;
use utoipa::IntoParams;
use uuid::Uuid;

/// Query parameters for SBOM correlation.
#[derive(Debug, Default, Deserialize, IntoParams)]
struct SbomCorrelationParams {
    /// When true, include components that have no correlation evidence.
    #[serde(default)]
    include_unmatched: bool,
}

#[cfg(test)]
mod test;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_ro: db::ReadOnly,
) {
    let service = CorrelationService::default();
    config
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(service))
        .service(get_sbom_correlation)
        .service(query_correlation);
}

/// Get correlation verdicts for an SBOM.
#[utoipa::path(
    tag = "correlation",
    operation_id = "getSbomCorrelation",
    params(
        ("id" = Uuid, Path, description = "SBOM ID"),
        SbomCorrelationParams,
    ),
    responses(
        (status = 200, description = "Correlation verdicts for the SBOM", body = CorrelationResult),
    ),
)]
#[get("/v3/correlation/sbom/{id}")]
async fn get_sbom_correlation(
    sbom_id: web::Path<Uuid>,
    params: web::Query<SbomCorrelationParams>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = service
        .correlate_sbom(*sbom_id, params.include_unmatched, &tx)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Query parameters for identifier lookup.
#[derive(Debug, Deserialize, IntoParams)]
struct IdentifierQuery {
    /// The kind of the identifier.
    kind: IdentifierKind,
    /// The identifier value to search for. Digests use the format `[<algorithm>:]<value>`.
    q: String,
}

/// Query for advisory/vulnerability matches by identifier.
///
/// Matches the value only as the given identifier kind against advisories
/// that reference it.
#[utoipa::path(
    tag = "correlation",
    operation_id = "queryCorrelation",
    params(IdentifierQuery),
    responses(
        (status = 200, description = "Matching advisories and vulnerabilities", body = QueryResult),
    ),
)]
#[get("/v3/correlation/query")]
async fn query_correlation(
    params: web::Query<IdentifierQuery>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let IdentifierQuery { kind, q: value } = params.into_inner();
    let result = service
        .query_identifier(IdentifierRef { kind, value }, &tx)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}
