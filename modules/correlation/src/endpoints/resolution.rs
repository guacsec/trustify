use crate::{
    error::Error,
    model::*,
    service::{CorrelationService, resolution::store},
};
use actix_web::{HttpResponse, Responder, delete, get, post, put, web};
use sea_orm::TransactionTrait;
use trustify_auth::{
    CreateCorrelationOption, DeleteCorrelationOption, ReadAdvisory, ReadCorrelationOption,
    UpdateCorrelationOption,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require, Requirement},
};
use trustify_common::capability::{Correlation, RequireCapability};
use trustify_common::db;
use uuid::Uuid;

/// List provider aliases
///
/// Provider aliases map the identifiers stated in SBOMs and advisories to a canonical
/// provider. They are applied when resolving verdicts, without re-extracting evidence.
#[utoipa::path(tag="correlation-configuration",operation_id="listProviderAliases",responses(
    (status=200,description="All provider aliases",body=Vec<ProviderAlias>),
    (status=401,description="The user was not authenticated"),
    (status=403,description="Insufficient permissions"),
    (status=422,description="Correlation capability disabled")
))]
#[get("/v3/correlation/provider-alias")]
async fn aliases(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(store::list_aliases(&tx).await?))
}
/// Create a provider alias
#[utoipa::path(tag="correlation-configuration",operation_id="createProviderAlias",request_body=ProviderAliasData,responses(
    (status=201,description="The created provider alias",body=ProviderAlias),
    (status=400,description="The provider or an alias is empty"),
    (status=409,description="The provider or an alias already belongs to another provider alias"),
    (status=401,description="The user was not authenticated"),
    (status=403,description="Insufficient permissions"),
    (status=422,description="Correlation capability disabled")
))]
#[post("/v3/correlation/provider-alias")]
async fn create_alias(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadWrite>,
    data: web::Json<ProviderAliasData>,
    _: Require<CreateCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = store::save_alias(None, data.into_inner(), &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::Created().json(result))
}
/// Replace a provider alias
#[utoipa::path(tag="correlation-configuration",operation_id="updateProviderAlias",params(("id"=Uuid,Path,description="ID of the provider alias")),request_body=ProviderAliasData,responses(
    (status=200,description="The updated provider alias",body=ProviderAlias),
    (status=400,description="The provider or an alias is empty"),
    (status=404,description="The provider alias does not exist"),
    (status=409,description="The provider or an alias already belongs to another provider alias"),
    (status=401,description="The user was not authenticated"),
    (status=403,description="Insufficient permissions"),
    (status=422,description="Correlation capability disabled")
))]
#[put("/v3/correlation/provider-alias/{id}")]
async fn update_alias(
    _gate: RequireCapability<Correlation>,
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
/// Delete a provider alias
///
/// Deleting an unknown provider alias succeeds as well.
#[utoipa::path(tag="correlation-configuration",operation_id="deleteProviderAlias",params(("id"=Uuid,Path,description="ID of the provider alias")),responses(
    (status=204,description="The provider alias was deleted, or did not exist"),
    (status=401,description="The user was not authenticated"),
    (status=403,description="Insufficient permissions"),
    (status=422,description="Correlation capability disabled")
))]
#[delete("/v3/correlation/provider-alias/{id}")]
async fn remove_alias(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadWrite>,
    id: web::Path<Uuid>,
    _: Require<DeleteCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    store::delete_alias(*id, &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
/// Preview correlation verdicts with a temporary resolution context
///
/// Resolves the verdicts of an SBOM or an identifier with the given request context, e.g. a
/// component provider or product context. A preview changes request context only; it cannot
/// write aliases or evidence.
#[utoipa::path(tag="correlation",operation_id="previewCorrelation",request_body=PreviewRequest,responses(
    (status = 422, description = "Correlation capability disabled"),
    (status=200,description="The verdicts resolved with the request context",body=PreviewResult),
    (status=401,description="The user was not authenticated"),
    (status=403,description="Insufficient permissions")
))]
#[post("/v3/correlation/preview")]
async fn preview(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadOnly>,
    service: web::Data<CorrelationService>,
    data: web::Json<PreviewRequest>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, actix_web::Error> {
    let PreviewRequest { target, resolution } = data.into_inner();
    if matches!(&target, PreviewTarget::Sbom { .. }) {
        super::ReadSbomCorrelation::enforce(&authorizer, &user)?;
    }
    let tx = db.begin().await.map_err(Error::from)?;
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
