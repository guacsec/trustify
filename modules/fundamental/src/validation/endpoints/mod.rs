use crate::validation::{model::ValidationReportSummary, service::ValidationService};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadValidation, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    id::Id,
    model::{Paginated, PaginatedResults},
};
use utoipa::IntoParams;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: db::ReadOnly,
    cache: PaginationCache,
) {
    let service = ValidationService::new(cache);

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(list_validation_reports)
        .service(get_validation_reports);
}

/// Filters that cannot be expressed as columns of the report itself.
#[derive(Clone, Debug, Default, IntoParams, serde::Deserialize)]
pub struct DocumentFilter {
    /// Name of the document: an SBOM's describing node, or an advisory
    /// identifier. Neither is unique, so this can match several documents.
    pub name: Option<String>,
}

#[utoipa::path(
    tag = "validation",
    operation_id = "listValidationReports",
    params(
        DocumentFilter,
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching validation reports", body = PaginatedResults<ValidationReportSummary>),
    ),
)]
#[get("/v3/validation")]
/// List validation reports
pub async fn list_validation_reports(
    state: web::Data<ValidationService>,
    db: web::Data<db::ReadOnly>,
    web::Query(filter): web::Query<DocumentFilter>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadValidation>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;

    Ok(HttpResponse::Ok().json(match &filter.name {
        Some(name) => state.get_by_name(name, paginated, &tx).await?,
        None => state.list(search, paginated, &tx).await?,
    }))
}

#[utoipa::path(
    tag = "validation",
    operation_id = "getValidationReports",
    params(
        ("key" = Id, Path, description = "Identifier of the document, either a digest e.g. `sha256:<hex>` or `urn:uuid:<uuid>` of an ingested SBOM or advisory"),
    ),
    responses(
        (status = 200, description = "Validation reports for the document", body = Vec<ValidationReportSummary>),
        (status = 400, description = "The key could not be interpreted as a document identifier"),
    ),
)]
#[get("/v3/validation/{key}")]
/// Retrieve the validation reports of one document
pub async fn get_validation_reports(
    state: web::Data<ValidationService>,
    db: web::Data<db::ReadOnly>,
    key: web::Path<String>,
    _: Require<ReadValidation>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    let id = key.parse::<Id>().map_err(crate::Error::from)?;

    Ok(HttpResponse::Ok().json(state.get(id, &tx).await?))
}

#[cfg(test)]
mod test;
