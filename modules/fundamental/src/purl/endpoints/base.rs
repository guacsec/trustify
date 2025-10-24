use crate::{
    Error,
    db::DatabaseExt,
    purl::{
        model::{details::base_purl::BasePurlDetails, summary::base_purl::BasePurlSummary},
        service::PurlService,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{
    db::{Database, query::Query},
    id::IdError,
    model::{Paginated, PaginatedResults},
    purl::Purl,
};

#[utoipa::path(
    operation_id = "getBasePurl",
    tag = "purl",
    params(
        ("key" = String, Path, description = "opaque identifier for a base PURL, or a URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Details for the versionless base PURL", body = BasePurlDetails),
    ),
)]
#[get("/v2/purl/base/{key}")]
/// Retrieve details about a base versionless pURL
pub async fn get_base_purl(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    if key.starts_with("pkg:") {
        let purl = Purl::from_str(&key).map_err(|e| Error::IdKey(IdError::Purl(e)))?;
        Ok(HttpResponse::Ok().json(service.base_purl_by_purl(&purl, &tx).await?))
    } else {
        let uuid = Uuid::from_str(&key).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
        Ok(HttpResponse::Ok().json(service.base_purl_by_uuid(&uuid, &tx).await?))
    }
}

#[utoipa::path(
    operation_id = "listBasePurls",
    tag = "purl",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching versionless base PURL", body = PaginatedResults<BasePurlSummary>),
    ),
)]
#[get("/v2/purl/base")]
/// List base versionless pURLs
pub async fn all_base_purls(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(service.base_purls(search, paginated, &tx).await?))
}
