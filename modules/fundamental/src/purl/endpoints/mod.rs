use crate::{
    Error,
    db::DatabaseExt,
    endpoints::Deprecation,
    purl::{
        model::{
            RecommendRequest, RecommendResponse, details::purl::PurlDetails,
            summary::purl::PurlSummary,
        },
        service::PurlService,
    },
};
use actix_web::{HttpResponse, Responder, get, post, web};
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use trustify_auth::{ReadAdvisory, ReadSbom, authorizer::Require};
use trustify_common::{
    db::{Database, query::Query},
    id::IdError,
    model::{Paginated, PaginatedResults},
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
        .service(recommend) // Must be before `get` to avoid {key} matching "recommend"
        .service(all)
        .service(get);
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
    let tx = db.begin_read().await?;
    if key.starts_with("pkg") {
        let purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(service.purl_by_purl(&purl, deprecated, &tx).await?))
    } else {
        let id = Uuid::from_str(&key).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
        Ok(HttpResponse::Ok().json(service.purl_by_uuid(&id, deprecated, &tx).await?))
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
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(service.purls(search, paginated, &tx).await?))
}

#[utoipa::path(
    operation_id = "recommend",
    tag = "purl",
    request_body = RecommendRequest,
    responses(
        (status = 200, description = "Get recommendations and remediations for provided purls", body = RecommendResponse)
    )
)]
#[post("/v2/purl/recommend")]
pub async fn recommend(
    purl_service: web::Data<PurlService>,
    db: web::Data<Database>,
    request: web::Json<RecommendRequest>,
    _: Require<ReadAdvisory>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let recommendations = purl_service.recommend_purls(&request.purls, &tx).await?;

    let response = RecommendResponse { recommendations };

    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod test;
