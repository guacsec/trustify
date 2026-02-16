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
    CreateSbomGroup, DeleteSbomGroup, ReadSbom, ReadSbomGroup, UpdateSbom, UpdateSbomGroup,
    authorizer::Require,
};
use trustify_common::{
    db::{Database, query::Query},
    endpoints::extract_revision,
    model::{Paginated, Revisioned},
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
        .service(delete)
        .service(read_assignments)
        .service(update_assignments)
        .service(bulk_update_assignments);
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
            body = GroupListResult,
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
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let result = service.list(options, pagination, query, &tx).await?;

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
    let Revisioned {
        revision,
        value: id,
    } = db
        .transaction(async |tx| service.create(group, tx).await)
        .await?;

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
        (status = 409, description = "The group has child groups and cannot be deleted"),
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
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let group = service.read(&id, &tx).await?;

    Ok(match group {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "readSbomGroupAssignments",
    params(
        ("id", Path, description = "The ID of the SBOM"),
    ),
    responses(
        (status = 200, description = "The SBOM was found and assignments returned"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The SBOM was not found"),
    )
)]
#[get("/v2/group/sbom-assignment/{id}")]
/// Get SBOM group assignments
async fn read_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let assignments = service.read_assignments(&id, &tx).await?;

    Ok(match assignments {
        Some(Revisioned { value, revision }) => HttpResponse::Ok()
            .append_header((header::ETAG, ETag(EntityTag::new_strong(revision))))
            .json(value),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "updateSbomGroupAssignments",
    request_body = Vec<String>,
    params(
        ("id", Path, description = "The ID of the SBOM to update"),
        ("if-match" = Option<String>, Header, description = "The revision of the SBOM assignments"),
    ),
    responses(
        (status = 204, description = "The SBOM assignments were updated"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 412, description = "The requested revision is not the current revision"),
    )
)]
#[put("/v2/group/sbom-assignment/{id}")]
/// Update SBOM group assignments
async fn update_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    web::Json(group_ids): web::Json<Vec<String>>,
    web::Header(if_match): web::Header<IfMatch>,
    _: Require<UpdateSbom>,
) -> actix_web::Result<impl Responder> {
    let revision = extract_revision(&if_match);

    db.transaction(async |tx| {
        service
            .update_assignments(&id, revision, group_ids, tx)
            .await
    })
    .await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbomGroup",
    operation_id = "bulkUpdateSbomGroupAssignments",
    request_body = BulkAssignmentRequest,
    responses(
        (status = 204, description = "The SBOM assignments were updated"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[put("/v2/group/sbom-assignment")]
/// Bulk update SBOM group assignments
async fn bulk_update_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    web::Json(request): web::Json<BulkAssignmentRequest>,
    _: Require<UpdateSbom>,
) -> actix_web::Result<impl Responder> {
    db.transaction(async |tx| {
        service
            .bulk_update_assignments(request.sbom_ids, request.group_ids, tx)
            .await
    })
    .await?;

    Ok(HttpResponse::NoContent().finish())
}
