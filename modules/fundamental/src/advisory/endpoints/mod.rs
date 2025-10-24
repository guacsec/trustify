mod config;
mod label;
#[cfg(test)]
mod test;

use crate::{
    Error,
    advisory::{
        model::{AdvisoryDetails, AdvisorySummary},
        service::AdvisoryService,
    },
    common::service::delete_doc,
    db::DatabaseExt,
    endpoints::Deprecation,
};
use actix_web::{HttpResponse, Responder, delete, get, http::header, post, web};
use config::Config;
use futures_util::TryStreamExt;
use sea_orm::TransactionTrait;
use std::str::FromStr;
use time::OffsetDateTime;
use trustify_auth::{CreateAdvisory, DeleteAdvisory, ReadAdvisory, authorizer::Require};
use trustify_common::{
    db::{Database, query::Query},
    decompress::decompress_async,
    id::Id,
    model::{BinaryData, Paginated, PaginatedResults},
};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};
use trustify_module_storage::service::StorageBackend;
use trustify_query::TrustifyQuery;
use trustify_query_derive::Query;
use utoipa::IntoParams;
use uuid::Uuid;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: Database,
    upload_limit: usize,
) {
    let advisory_service = AdvisoryService::new(db.clone());

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(advisory_service))
        .app_data(web::Data::new(Config { upload_limit }))
        .service(all)
        .service(get)
        .service(delete)
        .service(upload)
        .service(download)
        .service(label::set)
        .service(label::update)
        .service(label::all);
}

#[allow(dead_code)]
#[derive(Query)]
struct AdvisoryQuery {
    id: Uuid,
    identifier: String,
    version: Option<String>,
    document_id: String,
    deprecated: bool,
    issuer_id: Option<Uuid>,
    published: Option<OffsetDateTime>,
    modified: Option<OffsetDateTime>,
    withdrawn: Option<OffsetDateTime>,
    title: Option<String>,
    ingested: OffsetDateTime,
    label: String,
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "listAdvisories",
    params(
        TrustifyQuery<AdvisoryQuery>,
        Paginated,
        Deprecation,
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedResults<AdvisorySummary>),
    ),
)]
#[get("/v2/advisory")]
/// List advisories
pub async fn all(
    state: web::Data<AdvisoryService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(Deprecation { deprecated }): web::Query<Deprecation>,
    _: Require<ReadAdvisory>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(
        state
            .fetch_advisories(search, paginated, deprecated, &tx)
            .await?,
    ))
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "getAdvisory",
    params(
        ("key" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "The advisory could not be found"),
    ),
)]
#[get("/v2/advisory/{key}")]
/// Get an advisory
pub async fn get(
    state: web::Data<AdvisoryService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    _: Require<ReadAdvisory>,
) -> actix_web::Result<impl Responder> {
    let hash_key = Id::from_str(&key).map_err(Error::IdKey)?;
    let tx = db.begin_read().await?;
    let fetched = state.fetch_advisory(hash_key, &tx).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "deleteAdvisory",
    params(
        ("key" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "The advisory could not be found"),
    ),
)]
#[delete("/v2/advisory/{key}")]
/// Delete an advisory
pub async fn delete(
    i: web::Data<IngestorService>,
    service: web::Data<AdvisoryService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    _: Require<DeleteAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;

    let id = Id::from_str(&key)?;
    match service.fetch_advisory(id, &tx).await? {
        Some(v) => match service.delete_advisory(v.head.uuid, &tx).await? {
            false => Ok(HttpResponse::NotFound().finish()),
            true => {
                tx.commit().await?;
                if let Err(e) = delete_doc(&v.source_document, i.storage()).await {
                    log::warn!("Ignoring {e}");
                }
                Ok(HttpResponse::Ok().json(v))
            }
        },
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

#[derive(IntoParams, Clone, Debug, PartialEq, Eq, serde::Deserialize)]
struct UploadParams {
    /// Optional issuer if it cannot be determined from advisory contents.
    #[serde(default)]
    issuer: Option<String>,
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
    /// The format of the uploaded document.
    #[serde(default = "default_format")]
    #[param(inline)]
    format: Format,
}

const fn default_format() -> Format {
    Format::Advisory
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "uploadAdvisory",
    request_body = inline(BinaryData),
    params(UploadParams),
    responses(
        (status = 201, description = "Upload a file"),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/v2/advisory")]
/// Upload a new advisory
pub async fn upload(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    web::Query(UploadParams {
        issuer,
        labels,
        format,
    }): web::Query<UploadParams>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
    _: Require<CreateAdvisory>,
) -> Result<impl Responder, Error> {
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0), config.upload_limit).await??;
    let result = service
        .ingest(
            &bytes,
            format,
            labels,
            issuer,
            Cache::Skip, /* we only cache SBOMs */
        )
        .await?;
    log::info!("Uploaded Advisory: {}", result.id);
    Ok(HttpResponse::Created().json(result))
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "downloadAdvisory",
    params(
        ("key" = Id, Path),
    ),
    responses(
        (status = 200, description = "Download a an advisory", body = inline(BinaryData)),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/v2/advisory/{key}/download")]
/// Download an advisory document
pub async fn download(
    db: web::Data<Database>,
    ingestor: web::Data<IngestorService>,
    advisory: web::Data<AdvisoryService>,
    key: web::Path<String>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    // the user requested id
    let id = Id::from_str(&key).map_err(Error::IdKey)?;
    let tx = db.begin_read_snapshot().await?;

    // look up document by id
    let Some(advisory) = advisory.fetch_advisory(id, &tx).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let stream = ingestor
        .storage()
        .retrieve(advisory.source_document.try_into()?)
        .await
        .map_err(Error::Storage)?
        .map(|stream| stream.map_err(Error::Storage));

    Ok(match stream {
        Some(s) => HttpResponse::Ok().streaming(s),
        None => HttpResponse::NotFound().finish(),
    })
}
