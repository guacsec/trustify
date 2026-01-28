use super::service::{Error, ImporterService, PatchError};
use crate::model::{Importer, ImporterConfiguration, ImporterReport};
use actix_web::{
    HttpResponse, Responder, delete, get,
    guard::{self, Guard, GuardContext},
    http::header::{self, ETag, EntityTag, IfMatch},
    patch, post, put, web,
};
use std::convert::Infallible;
use trustify_auth::{
    CreateImporter, DeleteImporter, ReadImporter, UpdateImporter, authorizer::Require,
};
use trustify_common::{
    db::{Database, query::Query},
    endpoints::extract_revision,
    model::{Paginated, PaginatedResults, Revisioned},
};

/// mount the "importer" module
pub fn configure(svc: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    svc.app_data(web::Data::new(ImporterService::new(db)))
        .service(list)
        .service(create)
        .service(read)
        .service(update)
        .service(patch_json_merge)
        .service(delete)
        .service(get_reports)
        .service(set_enabled)
        .service(force);
}

#[utoipa::path(
    tag = "importer",
    operation_id = "listImporters",
    responses(
        (status = 200, description = "List importer configurations", body = [Importer])
    )
)]
#[get("/v2/importer")]
/// List importer configurations
async fn list(
    service: web::Data<ImporterService>,
    _: Require<ReadImporter>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(service.list().await?))
}

#[utoipa::path(
    tag = "importer",
    operation_id = "createImporter",
    request_body = ImporterConfiguration,
    params(
        ("name", Path, description = "The name of the importer"),
    ),
    responses(
        (status = 201, description = "Created a new importer configuration"),
        (status = 409, description = "An importer with that name already exists")
    )
)]
#[post("/v2/importer/{name}")]
/// Create a new importer configuration
async fn create(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Json(configuration): web::Json<ImporterConfiguration>,
    _: Require<CreateImporter>,
) -> Result<impl Responder, Error> {
    service.create(name.into_inner(), configuration).await?;
    Ok(HttpResponse::Created().finish())
}

#[utoipa::path(
    tag = "importer",
    operation_id = "getImporter",
    params(
        ("name", Path, description = "The name of the importer"),
    ),
    responses(
        (status = 200, description = "Retrieved importer configuration",
            body = Revisioned<Importer>,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 404, description = "The importer could not be found")
    )
)]
#[get("/v2/importer/{name}")]
/// Get an importer configuration
async fn read(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    _: Require<ReadImporter>,
) -> Result<Option<impl Responder>, Error> {
    Ok(service
        .read(&name)
        .await?
        .map(|Revisioned { value, revision }| {
            HttpResponse::Ok()
                .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
                .json(value)
        }))
}

#[utoipa::path(
    tag = "importer",
    operation_id = "updateImporter",
    request_body = ImporterConfiguration,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the importer configuration"),
        (status = 409, description = "The importer could not be found"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/v2/importer/{name}")]
/// Update an existing importer configuration
async fn update(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(configuration): web::Json<ImporterConfiguration>,
    _: Require<UpdateImporter>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .update_configuration(&name, revision, configuration)
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "importer",
    operation_id = "patchImporter",
    request_body(
        content = serde_json::Value,
        content_type = guards::JSON_MERGE_CONTENT_TYPE,
    ),
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Created a new importer configuration"),
        (status = 409, description = "The importer could not be found"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[patch("/v2/importer/{name}", guard = "guards::json_merge")]
/// Update an existing importer configuration
async fn patch_json_merge(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(patch): web::Json<serde_json::Value>,
    _: Require<UpdateImporter>,
) -> Result<impl Responder, PatchError<serde_json::Error>> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .patch_configuration(&name, revision, |config| {
            let mut json = serde_json::to_value(&config)?;
            json_merge_patch::json_merge_patch(&mut json, &patch);
            serde_json::from_value(json)
        })
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "importer",
    operation_id = "enableImporter",
    request_body = bool,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the enable state"),
        (status = 404, description = "The importer could not be found"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[put("/v2/importer/{name}/enabled")]
/// Update an existing importer configuration
async fn set_enabled(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    web::Json(state): web::Json<bool>,
    _: Require<UpdateImporter>,
) -> Result<impl Responder, PatchError<Infallible>> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service
        .patch_configuration(&name, revision, |mut configuration| {
            configuration.disabled = !state;
            Ok(configuration)
        })
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "importer",
    operation_id = "forceRunImporter",
    request_body = bool,
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to update"),
    ),
    responses(
        (status = 201, description = "Updated the state"),
        (status = 404, description = "The importer could not be found"),
        (status = 412, description = "The provided if-match header did not match the stored revision"),
    )
)]
#[post("/v2/importer/{name}/force")]
/// Force an importer to run as soon as possible
async fn force(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<UpdateImporter>,
) -> Result<impl Responder, Error> {
    let revision = match &if_match {
        IfMatch::Any => None,
        IfMatch::Items(items) => items.first().map(|etag| etag.tag()),
    };

    service.reset(&name, revision).await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "importer",
    operation_id = "deleteImporter",
    params(
        ("name", Path, description = "The name of the importer"),
        ("if-match"=Option<String>, Header, description = "The revision to delete"),
    ),
    responses(
        (status = 201, description = "Delete the importer configuration"),
    )
)]
#[delete("/v2/importer/{name}")]
/// Delete an importer configuration
async fn delete(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<DeleteImporter>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    Ok(match service.delete(&name, revision).await? {
        true => HttpResponse::NoContent().finish(),
        false => HttpResponse::NoContent().finish(),
    })
}

#[utoipa::path(
    tag = "importer",
    operation_id = "listImporterReports",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Retrieved importer reports", body = PaginatedResults<ImporterReport>),
    )
)]
#[get("/v2/importer/{name}/report")]
/// Get reports for an importer
async fn get_reports(
    service: web::Data<ImporterService>,
    name: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadImporter>,
) -> Result<impl Responder, Error> {
    Ok(web::Json(
        service.get_reports(&name, search, paginated).await?,
    ))
}

mod guards {
    use super::*;

    pub const JSON_MERGE_CONTENT_TYPE: &str = "application/merge-patch+json";

    pub fn json_merge(ctx: &GuardContext) -> bool {
        guard::Header("content-type", JSON_MERGE_CONTENT_TYPE).check(ctx)
    }
}
