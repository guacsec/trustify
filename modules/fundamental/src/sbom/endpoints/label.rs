use crate::{
    Error,
    common::service::{DocumentType, fetch_labels},
    sbom::service::SbomService,
};
use actix_web::{HttpResponse, Responder, get, patch, put, web};
use sea_orm::TransactionTrait;
use serde::Deserialize;
use trustify_auth::{
    Permission, UpdateSbom,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
};
use trustify_common::{db, id::Id};
use trustify_entity::labels::{Labels, Update};
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
struct LabelQuery {
    #[serde(default)]
    filter_text: String,

    #[serde(default = "default::limit")]
    limit: u64,
}

mod default {
    pub const fn limit() -> u64 {
        10
    }
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "listSbomLabels",
    params(
        LabelQuery,
    ),
    responses(
        (status = 200, description = "List all unique key/value labels from all SBOMs", body = Vec<Value>),
    ),
)]
#[get("/v3/sbom-labels")]
/// List all unique key/value labels from all SBOMs
pub async fn all(
    db: web::Data<db::ReadOnly>,
    web::Query(query): web::Query<LabelQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder, Error> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let tx = db.begin().await?;
    let result = fetch_labels(DocumentType::Sbom, query.filter_text, query.limit, &tx).await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Modify existing labels of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "patchSbomLabels",
    request_body = Update,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Modified the labels of the SBOM"),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[patch("/v3/sbom/{id}/label")]
pub async fn update(
    sbom: web::Data<SbomService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<Id>,
    web::Json(update): web::Json<Update>,
    _: Require<UpdateSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = sbom
        .update_labels(id.into_inner(), |labels| update.apply_to(labels), &tx)
        .await?;
    tx.commit().await?;

    Ok(match result {
        Some(()) => HttpResponse::NoContent(),
        None => HttpResponse::NotFound(),
    })
}

/// Replace the labels of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "updateSbomLabels",
    request_body = Labels,
    params(
        ("id" = Id, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 204, description = "Replaced the labels of the SBOM"),
        (status = 404, description = "The SBOM could not be found"),
    ),
)]
#[put("/v3/sbom/{id}/label")]
pub async fn set(
    sbom: web::Data<SbomService>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<Id>,
    web::Json(labels): web::Json<Labels>,
    _: Require<UpdateSbom>,
) -> actix_web::Result<impl Responder, Error> {
    Ok(
        match sbom
            .set_labels(id.into_inner(), labels, db.as_ref())
            .await?
        {
            Some(()) => HttpResponse::NoContent(),
            None => HttpResponse::NotFound(),
        },
    )
}
