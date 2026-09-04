use crate::crypto::{
    model::{CryptoAlgorithmSummary, PolicyEvaluationRequest, PolicyEvaluationResponse},
    service::CryptoService,
};
use actix_web::{HttpResponse, Responder, get, post, web};
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    model::{Paginated, PaginatedResults},
};

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
        .service(evaluate_policy);
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "listCryptoAlgorithms",
    params(
        Query,
        Paginated,
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
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(state.list_algorithms(search, paginated, &tx).await?))
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
