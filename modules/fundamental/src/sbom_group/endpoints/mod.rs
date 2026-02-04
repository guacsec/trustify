#[cfg(test)]
mod test;

use super::{
    model::*,
    service::{ListOptions, SbomGroupService},
};
use crate::{Error, db::DatabaseExt};
use actix_web::{
    HttpRequest, HttpResponse, Responder, delete, get,
    http::header::{self, ETag, EntityTag, IfMatch},
    post, put, web,
};
use sea_orm::TransactionTrait;
use serde::Serialize;
use serde_json::json;
use trustify_auth::{
    CreateSbomGroup, DeleteSbomGroup, ReadSbomGroup, UpdateSbomGroup, authorizer::Require,
};
use trustify_common::{
    db::{Database, query::Query},
    endpoints::extract_revision,
    model::{Paginated, PaginatedResults, Revisioned},
};
use utoipa::ToSchema;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: Database,
    max_group_name_length: usize,
) {
    let service = SbomGroupService::new(max_group_name_length);

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(list)
        .service(create)
        .service(read)
        .service(update)
        .service(delete);
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "listSbomGroups",
    params(
        ListOptions,
        Paginated,
        Query,
    ),
    responses(
        (
            status = 200, description = "Executed the SBOM group query",
            body = PaginatedResults<GroupDetails>,
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
   )
)]
#[get("/v2/group/sbom")]
/// List SBOM groups
async fn list(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    web::Query(pagination): web::Query<Paginated>,
    web::Query(options): web::Query<ListOptions>,
    web::Query(query): web::Query<Query>,
    _: Require<ReadSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin_read().await?;
    let result = service.list(options, pagination, query, &tx).await?;
    tx.rollback().await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Serialize, ToSchema)]
struct CreateResponse {
    /// The ID of the newly created group
    id: String,
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "createSbomGroup",
    request_body = GroupRequest,
    responses(
        (
            status = 201, description = "Created the requested group",
            body = CreateResponse,
            headers(
                ("location" = String, description = "The relative URL to the created resource")
            )
        ),
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
        ("id", Path, description = "The ID of the group to delete"),
        ("if-match" = Option<String>, Header, description = "The revision to delete"),
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
        ("id", Path, description = "The ID of the group to update"),
        ("if-match" = Option<String>, Header, description = "The revision to update"),
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
/// Update an SBOM group
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
        ("id", Path, description = "The ID of the group to read"),
    ),
    responses(
        (
            status = 200, description = "The group was found and returned",
            body = Revisioned<Group>,
            headers(
                ("etag" = String, description = "Revision ID")
            )
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v2/group/sbom/{id}")]
/// Read the SBOM group information
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
