use crate::{
    error::Error,
    model::{
        AdvisoryStatement, CorrelationResult, IdentifierKind, IdentifierRef, QueryResult,
        SbomVerdictCounts, StatementKind, VerdictCountsRequest,
    },
    service::{CorrelationService, option::OptionService, statement::StatementService},
};
use actix_web::{HttpResponse, Responder, get, post, web};
use serde::Deserialize;
use trustify_auth::{ReadAdvisory, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache},
    model::Paginated,
};
use utoipa::IntoParams;
use uuid::Uuid;

/// Query parameters for SBOM correlation.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
struct SbomCorrelationParams {
    /// When true, include components that have no correlation evidence.
    #[serde(default)]
    include_unmatched: bool,
    #[serde(default)]
    include_explanation: bool,
    node_id: Option<String>,
    vulnerability_id: Option<String>,
}

mod freshness;
mod option;
mod resolution;
#[cfg(test)]
mod test;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_ro: db::ReadOnly,
    db_rw: db::ReadWrite,
    cache: PaginationCache,
) {
    let service = CorrelationService::default();
    config
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(db_rw))
        .app_data(web::Data::new(service))
        .app_data(web::Data::new(OptionService::new(cache.clone())))
        .app_data(web::Data::new(StatementService::new(cache)))
        .service(get_sbom_correlation)
        .service(list_advisory_statements)
        .service(count_verdicts)
        .service(query_correlation)
        .configure(option::configure)
        .configure(freshness::configure)
        .configure(resolution::configure);
}

/// Get correlation verdicts for an SBOM.
#[utoipa::path(
    tag = "correlation",
    operation_id = "getSbomCorrelation",
    params(
        ("id" = Uuid, Path, description = "SBOM ID"),
        SbomCorrelationParams,
    ),
    responses(
        (status = 200, description = "Correlation verdicts for the SBOM", body = CorrelationResult),
    ),
)]
#[get("/v3/correlation/sbom/{id}")]
async fn get_sbom_correlation(
    sbom_id: web::Path<Uuid>,
    params: web::Query<SbomCorrelationParams>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    freshness::snapshot(&tx).await?;
    let result = service
        .correlate_sbom_with(
            *sbom_id,
            params.include_unmatched,
            &crate::model::ResolutionRequest {
                include_explanation: params.include_explanation,
                node_id: params.node_id.clone(),
                vulnerability_id: params.vulnerability_id.clone(),
                ..Default::default()
            },
            &tx,
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Maximum number of SBOMs per verdict count request.
const MAX_VERDICT_COUNT_SBOMS: usize = 1000;

/// Count the verdicts of several SBOMs by status, e.g. for a list of SBOMs.
///
/// Returns one entry per requested SBOM, in the requested order.
#[utoipa::path(
    tag = "correlation",
    operation_id = "countVerdicts",
    request_body = VerdictCountsRequest,
    responses(
        (status = 200, description = "Verdict counts per SBOM", body = Vec<SbomVerdictCounts>),
        (status = 400, description = "Too many SBOMs requested"),
    ),
)]
#[post("/v3/correlation/verdict-counts")]
async fn count_verdicts(
    web::Json(request): web::Json<VerdictCountsRequest>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
) -> Result<impl Responder, Error> {
    if request.sbom_ids.len() > MAX_VERDICT_COUNT_SBOMS {
        return Err(Error::BadRequest(format!(
            "at most {MAX_VERDICT_COUNT_SBOMS} SBOMs per request"
        )));
    }

    let tx = db.begin().await?;
    freshness::snapshot(&tx).await?;
    let result = service.count_verdicts(&request.sbom_ids, &tx).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Query parameters for identifier lookup.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
struct IdentifierQuery {
    /// The kind of the identifier.
    kind: IdentifierKind,
    /// The identifier value to search for. Digests use the format `[<algorithm>:]<value>`.
    q: String,
    #[serde(default)]
    include_explanation: bool,
    provider: Option<String>,
    vulnerability_id: Option<String>,
}

/// Query for advisory/vulnerability matches by identifier.
///
/// Matches the value only as the given identifier kind against advisories
/// that reference it.
#[utoipa::path(
    tag = "correlation",
    operation_id = "queryCorrelation",
    params(IdentifierQuery),
    responses(
        (status = 200, description = "Matching advisories and vulnerabilities", body = QueryResult),
    ),
)]
#[get("/v3/correlation/query")]
async fn query_correlation(
    params: web::Query<IdentifierQuery>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let IdentifierQuery {
        kind,
        q: value,
        include_explanation,
        provider,
        vulnerability_id,
    } = params.into_inner();
    let result = service
        .query_identifier_with(
            IdentifierRef { kind, value },
            &crate::model::ResolutionRequest {
                include_explanation,
                vulnerability_id,
                component_provider: provider,
                ..Default::default()
            },
            &tx,
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Query parameters for listing advisory statements.
#[derive(Debug, Deserialize, IntoParams)]
struct StatementQuery {
    /// The kind of subject of the statements.
    #[param(inline)]
    kind: StatementKind,
    /// Only the statements for this vulnerability, e.g. `CVE-2024-1234`.
    vulnerability: Option<String>,
}

/// List the statuses an advisory states, about one kind of subject.
///
/// These are the facts as stored when the advisory was ingested, which correlation matches SBOMs
/// against. An unknown advisory has no statements.
#[utoipa::path(
    tag = "correlation",
    operation_id = "listAdvisoryStatements",
    params(
        ("id" = Uuid, Path, description = "The ID of the advisory"),
        StatementQuery,
        Paginated,
    ),
    responses(
        (status = 200, description = "The statements", body = inline(trustify_common::model::PaginatedResults<AdvisoryStatement>)),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    ),
)]
#[get("/v3/correlation/advisory/{id}/statement")]
async fn list_advisory_statements(
    advisory_id: web::Path<Uuid>,
    web::Query(query): web::Query<StatementQuery>,
    web::Query(paginated): web::Query<Paginated>,
    service: web::Data<StatementService>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let result = service
        .list(
            *advisory_id,
            query.kind,
            query.vulnerability.as_deref(),
            paginated,
            &tx,
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}
