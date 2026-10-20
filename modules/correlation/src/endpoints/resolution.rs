use crate::{
    error::Error,
    model::*,
    service::{CorrelationService, resolution::store},
};
use actix_web::{HttpResponse, Responder, delete, get, post, put, web};
use sea_orm::TransactionTrait;
use trustify_auth::{
    CreateCorrelationOption, DeleteCorrelationOption, ReadCorrelationOption,
    UpdateCorrelationOption, authorizer::Require,
};
use trustify_common::db;
use uuid::Uuid;

#[utoipa::path(tag="correlation",operation_id="listProviderAliases",responses((status=200,body=Vec<ProviderAlias>)))]
#[get("/v3/correlation/provider-alias")]
async fn aliases(
    db: web::Data<db::ReadOnly>,
    _: Require<ReadCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(store::list_aliases(&tx).await?))
}
#[utoipa::path(tag="correlation",operation_id="createProviderAlias",request_body=ProviderAliasData,responses((status=201,body=ProviderAlias)))]
#[post("/v3/correlation/provider-alias")]
async fn create_alias(
    db: web::Data<db::ReadWrite>,
    data: web::Json<ProviderAliasData>,
    _: Require<CreateCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = store::save_alias(None, data.into_inner(), &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::Created().json(result))
}
#[utoipa::path(tag="correlation",operation_id="updateProviderAlias",params(("id"=Uuid,Path)),request_body=ProviderAliasData,responses((status=200,body=ProviderAlias)))]
#[put("/v3/correlation/provider-alias/{id}")]
async fn update_alias(
    db: web::Data<db::ReadWrite>,
    id: web::Path<Uuid>,
    data: web::Json<ProviderAliasData>,
    _: Require<UpdateCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = store::save_alias(Some(*id), data.into_inner(), &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::Ok().json(result))
}
#[utoipa::path(tag="correlation",operation_id="deleteProviderAlias",params(("id"=Uuid,Path)),responses((status=204)))]
#[delete("/v3/correlation/provider-alias/{id}")]
async fn remove_alias(
    db: web::Data<db::ReadWrite>,
    id: web::Path<Uuid>,
    _: Require<DeleteCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    store::delete_alias(*id, &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
/// A preview changes request context only; it cannot write aliases or evidence.
#[utoipa::path(tag="correlation",operation_id="previewCorrelation",request_body=PreviewRequest,responses((status=200,body=PreviewResult)))]
#[post("/v3/correlation/preview")]
async fn preview(
    db: web::Data<db::ReadOnly>,
    service: web::Data<CorrelationService>,
    data: web::Json<PreviewRequest>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let PreviewRequest { target, resolution } = data.into_inner();
    super::freshness::snapshot(&tx).await?;
    let result = match target {
        PreviewTarget::Sbom { sbom_id } => PreviewResult::Sbom(
            service
                .correlate_sbom_with(sbom_id, false, &resolution, &tx)
                .await?,
        ),
        PreviewTarget::Identifier { identifier } => PreviewResult::Identifier(
            service
                .query_identifier_with(identifier, &resolution, &tx)
                .await?,
        ),
    };
    Ok(HttpResponse::Ok().json(result))
}

pub(super) fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(aliases)
        .service(create_alias)
        .service(update_alias)
        .service(remove_alias)
        .service(preview);
}
