//! Endpoints managing the options of the correlation engine.
//!
//! A changed option applies to documents extracted afterwards.

use crate::{
    error::Error,
    model::{CorrelationOption, CorrelationOptionData},
    service::option::OptionService,
};
use actix_web::{HttpResponse, Responder, delete, get, post, put, web};
use sea_orm::TransactionTrait;
use serde::Serialize;
use trustify_auth::{
    CreateCorrelationOption, DeleteCorrelationOption, ReadCorrelationOption,
    UpdateCorrelationOption, authorizer::Require,
};
use trustify_common::{db, model::Paginated};
use utoipa::ToSchema;
use uuid::Uuid;

/// The ID of a created option.
#[derive(Serialize, ToSchema)]
struct CreateResponse {
    id: Uuid,
}

/// List the correlation options.
#[utoipa::path(
    tag = "correlation",
    operation_id = "listCorrelationOptions",
    params(Paginated),
    responses(
        (status = 200, description = "The options", body = inline(trustify_common::model::PaginatedResults<CorrelationOption>)),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    ),
)]
#[get("/v3/correlation/option")]
async fn list(
    service: web::Data<OptionService>,
    db: web::Data<db::ReadOnly>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(service.list(paginated, &tx).await?))
}

/// Get a correlation option.
#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationOption",
    params(("id" = Uuid, Path, description = "The ID of the option")),
    responses(
        (status = 200, description = "The option", body = CorrelationOption),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The option doesn't exist"),
    ),
)]
#[get("/v3/correlation/option/{id}")]
async fn read(
    service: web::Data<OptionService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    _: Require<ReadCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    match service.get(*id, &tx).await? {
        Some(option) => Ok(HttpResponse::Ok().json(option)),
        None => Err(Error::NotFound(id.to_string())),
    }
}

/// Create a correlation option.
///
/// It applies to documents extracted afterwards.
#[utoipa::path(
    tag = "correlation",
    operation_id = "createCorrelationOption",
    request_body = CorrelationOptionData,
    responses(
        (status = 201, description = "The option was created", body = CreateResponse),
        (status = 400, description = "The value doesn't fit the key"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 409, description = "The publisher already has an option of that key"),
    ),
)]
#[post("/v3/correlation/option")]
async fn create(
    service: web::Data<OptionService>,
    db: web::Data<db::ReadWrite>,
    web::Json(data): web::Json<CorrelationOptionData>,
    _: Require<CreateCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let id = service.create(data, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Created()
        .append_header(("location", format!("/api/v3/correlation/option/{id}")))
        .json(CreateResponse { id }))
}

/// Update a correlation option.
///
/// It applies to documents extracted afterwards.
#[utoipa::path(
    tag = "correlation",
    operation_id = "updateCorrelationOption",
    request_body = CorrelationOptionData,
    params(("id" = Uuid, Path, description = "The ID of the option")),
    responses(
        (status = 204, description = "The option was updated"),
        (status = 400, description = "The value doesn't fit the key"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The option doesn't exist"),
        (status = 409, description = "The publisher already has an option of that key"),
    ),
)]
#[put("/v3/correlation/option/{id}")]
async fn update(
    service: web::Data<OptionService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<Uuid>,
    web::Json(data): web::Json<CorrelationOptionData>,
    _: Require<UpdateCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service.update(*id, data, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Delete a correlation option.
///
/// It applies to documents extracted afterwards.
#[utoipa::path(
    tag = "correlation",
    operation_id = "deleteCorrelationOption",
    params(("id" = Uuid, Path, description = "The ID of the option")),
    responses(
        (status = 204, description = "The option was deleted or did not exist"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    ),
)]
#[delete("/v3/correlation/option/{id}")]
async fn remove(
    service: web::Data<OptionService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<Uuid>,
    _: Require<DeleteCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service.delete(*id, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Register the option endpoints.
pub(super) fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(list)
        .service(read)
        .service(create)
        .service(update)
        .service(remove);
}
