use crate::{
    Error,
    crypto::{
        model::{
            CryptoAlgorithmSummary, CryptoSummary, PolicyEvaluationRequest,
            PolicyEvaluationResponse, RemediationImportItem, RemediationImportResult,
            RemediationMapping,
        },
        service::CryptoService,
    },
};
use actix_web::{HttpResponse, Responder, get, http::header, post, web};
use sea_orm::TransactionTrait;
use trustify_auth::{CreateMetadata, ReadSbom, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::sbom_crypto::CryptoAssetType;
use uuid::Uuid;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_rw: db::ReadWrite,
    db: db::ReadOnly,
    cache: PaginationCache,
) {
    let service = CryptoService::new(cache);
    config
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(list_algorithms)
        .service(get_summary)
        .service(list_sbom_crypto)
        .service(evaluate_policy)
        .service(import_remediations)
        .service(list_remediations);
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

/// Converts empty-string optional fields (from CSV blank columns) to `None`.
fn normalize_optional_strings(mut item: RemediationImportItem) -> RemediationImportItem {
    if item.algorithm_primitive.as_deref() == Some("") {
        item.algorithm_primitive = None;
    }
    if item.replacement_standard.as_deref() == Some("") {
        item.replacement_standard = None;
    }
    if item.replacement_primitive.as_deref() == Some("") {
        item.replacement_primitive = None;
    }
    item
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "importCryptoRemediations",
    request_body(
        description = "Algorithm-to-replacement mappings as a JSON array (application/json) \
                       or CSV rows (text/csv) with headers: algorithm_name, algorithm_primitive, \
                       replacement_name, replacement_standard, replacement_primitive",
        content(
            (Vec<RemediationImportItem> = "application/json"),
            (String = "text/csv"),
        ),
    ),
    responses(
        (status = 200, description = "Import result", body = RemediationImportResult),
        (status = 400, description = "The request body could not be parsed as valid JSON or CSV"),
    ),
)]
#[post("/v3/crypto/remediation/import")]
pub async fn import_remediations(
    state: web::Data<CryptoService>,
    db_rw: web::Data<db::ReadWrite>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
    _: Require<CreateMetadata>,
) -> Result<impl Responder, Error> {
    let is_csv = content_type
        .as_ref()
        .map(|ct| ct.0.essence_str() == "text/csv")
        .unwrap_or(false);

    let mappings: Vec<RemediationImportItem> = if is_csv {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(bytes.as_ref());
        reader
            .deserialize::<RemediationImportItem>()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::BadRequest(e.to_string().into(), None))?
            .into_iter()
            .map(normalize_optional_strings)
            .collect()
    } else {
        let parsed: Vec<RemediationImportItem> = serde_json::from_slice(&bytes)
            .map_err(|e| Error::BadRequest(e.to_string().into(), None))?;
        parsed.into_iter().map(normalize_optional_strings).collect()
    };

    let tx = db_rw.begin().await?;
    let count = state.import_remediations(mappings, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(RemediationImportResult { count }))
}

#[utoipa::path(
    tag = "crypto",
    operation_id = "listCryptoRemediations",
    responses(
        (status = 200, description = "All stored remediation mappings", body = Vec<RemediationMapping>),
    ),
)]
#[get("/v3/crypto/remediation")]
pub async fn list_remediations(
    state: web::Data<CryptoService>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(state.list_remediations(&tx).await?))
}

#[cfg(test)]
mod test;
