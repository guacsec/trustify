#[cfg(test)]
mod test;

use crate::{Error, db::DatabaseExt, sbom_group::model::*, sbom_group::service::SbomGroupService};
use actix_http::header;
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get,
    http::header::{ETag, EntityTag, IfMatch},
    post, put, web,
};
use sea_orm::TransactionTrait;
use serde_json::json;
use trustify_auth::{
    CreateSbomGroup, DeleteSbomGroup, ReadSbomGroup, UpdateSbomGroup, authorizer::Require,
};
use trustify_common::{db::Database, endpoints::extract_revision, model::Revisioned};

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: Database,
    max_group_name_length: usize,
) {
    let service = SbomGroupService::new(max_group_name_length);

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(create)
        .service(read)
        .service(update)
        .service(delete);
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "createSbomGroup",
    request_body = GroupRequest,
    responses(
        (status = 201, description = "Created the requested group"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The name of the group is not unique within the parent"),
    )
)]
#[post("/v2/group/sbom")]
/// Create a new SBOM group
async fn create(
    req: HttpRequest,
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    web::Json(group): web::Json<GroupRequest>,
    _: Require<CreateSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let Revisioned {
        revision,
        value: id,
    } = service.create(group, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Created()
        .append_header((header::LOCATION, format!("{}/{}", req.path(), id)))
        .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
        .json(json!({"id": id})))
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "deleteSbomGroup",
    request_body = GroupRequest,
    params(
        ("id", Query, description = "The ID of the group to delete"),
        ("IfMatch", Header, description = "The revision of the group to delete"),
    ),
    responses(
        (status = 204, description = "The group was deleted or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 412, description = "The requested revision is not the current revision of the group"),
    )
)]
#[delete("/v2/group/sbom/{id}")]
/// Delete an SBOM group
async fn delete(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<DeleteSbomGroup>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    let tx = db.begin().await?;
    service.delete(&id, revision, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "updateSbomGroup",
    request_body = GroupRequest,
    params(
        ("id", Query, description = "The ID of the group to update"),
        ("IfMatch", Header, description = "The revision of the group to update"),
    ),
    responses(
        (status = 204, description = "The group was delete or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The name of the group is not unique within the parent"),
        (status = 409, description = "Assigning the parent would create a cycle"),
        (status = 412, description = "The requested revision is not the current revision of the group"),
    )
)]
#[put("/v2/group/sbom/{id}")]
/// Create a new importer configuration
async fn update(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    web::Json(group): web::Json<GroupRequest>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<UpdateSbomGroup>,
) -> Result<impl Responder, Error> {
    let revision = extract_revision(&if_match);

    let tx = db.begin().await?;
    service.update(&id, revision, group, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "readSbomGroup",
    params(
        ("id", Query, description = "The ID of the group to read"),
    ),
    responses(
        (status = 200, description = "The group was found and returned"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v2/group/sbom/{id}")]
/// Create a new importer configuration
async fn read(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<ReadSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin_read().await?;
    let group = service.read(&id, &tx).await?;
    tx.rollback().await?;

    Ok(match group {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}
