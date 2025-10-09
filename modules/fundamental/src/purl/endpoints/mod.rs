use crate::{
    Error,
    endpoints::Deprecation,
    purl::{
        model::{details::purl::PurlDetails, summary::purl::PurlSummary},
        service::PurlService,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{
    db::Database, db::query::Query, id::IdError, model::Paginated, model::PaginatedResults,
    purl::Purl,
};

mod base;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let purl_service = PurlService::new();

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(purl_service))
        .service(base::get_base_purl)
        .service(base::all_base_purls)
        .service(get)
        .service(all);
}

#[utoipa::path(
    operation_id = "getPurl",
    tag = "purl",
    params(
        Deprecation,
        ("key" = String, Path, description = "opaque identifier for a fully-qualified PURL, or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Details for the qualified PURL", body = PurlDetails),
    ),
)]
#[get("/v2/purl/{key}")]
/// Retrieve details of a fully-qualified pURL
pub async fn get(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(Deprecation { deprecated }): web::Query<Deprecation>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg") {
        let purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(service.purl_by_purl(&purl, deprecated, db.as_ref()).await?))
    } else {
        let id = Uuid::from_str(&key).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
        Ok(HttpResponse::Ok().json(service.purl_by_uuid(&id, deprecated, db.as_ref()).await?))
    }
}

#[utoipa::path(
    operation_id = "listPurl",
    tag = "purl",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching qualified PURLs", body = PaginatedResults<PurlSummary>),
    ),
)]
#[get("/v2/purl")]
/// List fully-qualified pURLs
pub async fn all(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.purls(search, paginated, db.as_ref()).await?))
}

#[cfg(test)]
mod test;
