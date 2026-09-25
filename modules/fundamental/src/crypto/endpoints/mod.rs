use crate::crypto::{
    model::{
        CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationRequest, PolicyEvaluationResponse,
    },
    service::CryptoService,
};
use actix_web::{HttpResponse, Responder, get, post, web};
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::sbom_crypto::CryptoAssetType;
use uuid::Uuid;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: db::ReadOnly,
    cache: PaginationCache,
) {
    let service = CryptoService::new(cache);
    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(list_algorithms)
        .service(get_summary)
        .service(list_sbom_crypto)
        .service(evaluate_policy);
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct CryptoFilterParams {
    /// Filter by crypto asset type
    #[param(inline)]
    pub asset_type: Option<CryptoAssetType>,
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "listCryptoAlgorithms",
    params(
        Query,
        Paginated,
        CryptoFilterParams,
    ),
    responses(
        (status = 200, description = "Matching crypto algorithms", body = PaginatedResults<CryptoAlgorithmSummary>),
    ),
)]
#[get("/v3/crypto/algorithm")]
pub async fn list_algorithms(
    state: web::Data<CryptoService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(filter): web::Query<CryptoFilterParams>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(
        state
            .list_algorithms(search, paginated, filter.asset_type, None, &tx)
            .await?,
    ))
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "getCryptoSummary",
    responses(
        (status = 200, description = "Crypto KPI summary", body = CryptoSummary),
    ),
)]
#[get("/v3/crypto/summary")]
pub async fn get_summary(
    state: web::Data<CryptoService>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(state.fetch_summary(&tx).await?))
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "listSbomCrypto",
    params(
        ("id", Path, description = "ID of the SBOM to get crypto assets for"),
        Query,
        Paginated,
        CryptoFilterParams,
    ),
    responses(
        (status = 200, description = "Crypto assets for the SBOM", body = PaginatedResults<CryptoAlgorithmSummary>),
    ),
)]
#[get("/v3/sbom/{id}/crypto")]
pub async fn list_sbom_crypto(
    state: web::Data<CryptoService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(filter): web::Query<CryptoFilterParams>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(
        state
            .list_algorithms(
                search,
                paginated,
                filter.asset_type,
                Some(id.into_inner()),
                &tx,
            )
            .await?,
    ))
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "evaluateCryptoPolicy",
    request_body = PolicyEvaluationRequest,
    responses(
        (status = 200, description = "Policy evaluation results", body = PolicyEvaluationResponse),
    ),
)]
#[post("/v3/crypto/policy/evaluate")]
pub async fn evaluate_policy(
    state: web::Data<CryptoService>,
    db: web::Data<db::ReadOnly>,
    body: web::Json<PolicyEvaluationRequest>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(state.evaluate_policy(body.sbom_id, &tx).await?))
}

#[cfg(test)]
mod test;
