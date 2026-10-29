use crate::{
    error::Error,
    model::{
        AdvisoryStatement, ComponentRef, ConfidenceCatalog, IdentifierKind, IdentifierRef,
        QueryResult, SbomVerdictCounts, SbomVerdictPage, StatementKind, VerdictCountsRequest,
        VerdictStatus,
    },
    service::{CorrelationService, confidence, option::OptionService, statement::StatementService},
};
use actix_web::{HttpResponse, Responder, get, post, web};
use serde::Deserialize;
use trustify_auth::{ReadAdvisory, ReadSbom, all, authorizer::Require};
use trustify_common::capability::{Correlation, RequireCapability};
use trustify_common::{
    db::{self, DatabaseExt, pagination_cache::PaginationCache},
    model::{Paginated, PaginatedResults},
};
use utoipa::IntoParams;
use uuid::Uuid;

/// Query parameters for SBOM correlation.
#[derive(Debug, Default, Deserialize, IntoParams)]
struct SbomCorrelationParams {
    /// When true, include an explanation of how each verdict was resolved.
    #[serde(default)]
    include_explanation: bool,
    /// Only the verdicts of this SBOM node.
    node_id: Option<String>,
    /// Only the verdicts for this vulnerability, e.g. `CVE-2024-1234`.
    vulnerability_id: Option<String>,
    /// Only verdicts with this resolved status.
    status: Option<VerdictStatus>,
}

#[derive(Debug, Deserialize, IntoParams)]
struct UnmatchedParams {
    /// Only this SBOM node.
    node_id: Option<String>,
}

mod freshness;
mod option;
mod resolution;
#[cfg(test)]
mod test;

all!(ReadSbomCorrelation -> ReadSbom, ReadAdvisory);

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
        .app_data(web::Data::new(cache.clone()))
        .app_data(web::Data::new(OptionService::new(cache.clone())))
        .app_data(web::Data::new(StatementService::new(cache)))
        .service(get_sbom_correlation)
        .service(get_sbom_unmatched)
        .service(list_advisory_statements)
        .service(count_verdicts)
        .service(query_correlation)
        .service(get_confidence_catalog)
        .configure(option::configure)
        .configure(freshness::configure)
        .configure(resolution::configure);
}

/// Get correlation verdicts for an SBOM, ordered by node ID and vulnerability ID.
/// Each item contains all evidence for one complete verdict.
/// A zero limit returns no items; the total is computed only when requested.
#[utoipa::path(
    tag = "correlation",
    operation_id = "getSbomCorrelation",
    params(
        ("id" = String, Path, description = "SBOM ID"),
        SbomCorrelationParams,
        Paginated,
    ),
    responses(
        (status = 422, description = "Correlation capability disabled"),
        (status = 200, description = "Correlation verdicts for the SBOM", body = SbomVerdictPage),
        (status = 400, description = "Invalid pagination or query parameters"),
        (status = 404, description = "SBOM ID not found"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "Insufficient permissions"),
    ),
)]
#[get("/v3/correlation/sbom/{id}")]
#[allow(clippy::too_many_arguments)]
async fn get_sbom_correlation(
    _gate: RequireCapability<Correlation>,
    sbom_id: web::Path<String>,
    params: web::Query<SbomCorrelationParams>,
    web::Query(paginated): web::Query<Paginated>,
    cache: web::Data<PaginationCache>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadSbomCorrelation>,
) -> Result<impl Responder, Error> {
    let sbom_id = Uuid::parse_str(&sbom_id).map_err(|_| Error::NotFound(sbom_id.into_inner()))?;
    let tx = db.begin_read().await?;
    let result = service
        .filtered_verdict_page(
            sbom_id,
            &crate::model::ResolutionRequest {
                include_explanation: params.include_explanation,
                node_id: params.node_id.clone(),
                vulnerability_id: params.vulnerability_id.clone(),
                ..Default::default()
            },
            params.status,
            paginated,
            &cache,
            &tx,
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// List components without correlation evidence, excluding the SBOM root.
/// Ordered by node ID. Evidence is checked independently of verdict filters.
#[utoipa::path(tag = "correlation", operation_id = "getSbomUnmatched",
    params(("id" = String, Path, description = "SBOM ID"), UnmatchedParams, Paginated),
    responses(
        (status = 200, description = "A page of unmatched components", body = inline(PaginatedResults<ComponentRef>)),
        (status = 400, description = "Invalid pagination or query parameters"),
        (status = 404, description = "SBOM ID not found"),
        (status = 422, description = "Correlation capability disabled"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
#[get("/v3/correlation/sbom/{id}/unmatched")]
#[allow(clippy::too_many_arguments)]
async fn get_sbom_unmatched(
    _gate: RequireCapability<Correlation>,
    sbom_id: web::Path<String>,
    params: web::Query<UnmatchedParams>,
    web::Query(paginated): web::Query<Paginated>,
    service: web::Data<CorrelationService>,
    cache: web::Data<PaginationCache>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadSbomCorrelation>,
) -> Result<impl Responder, Error> {
    let sbom_id = Uuid::parse_str(&sbom_id).map_err(|_| Error::NotFound(sbom_id.into_inner()))?;
    let tx = db.begin_read().await?;
    let result = service
        .unmatched_page(sbom_id, params.node_id.as_deref(), paginated, &cache, &tx)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Get the factors of a match confidence
///
/// Lists all factors a match confidence can be made of, with the version range rules as
/// currently configured. A match confidence is the product of its factors.
#[utoipa::path(
    tag = "correlation",
    operation_id = "getCorrelationConfidence",
    responses(
        (status = 422, description = "Correlation capability disabled"),
        (status = 200, description = "The factors of a match confidence", body = ConfidenceCatalog),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "Insufficient permissions"),
    ),
)]
#[get("/v3/correlation/confidence")]
async fn get_confidence_catalog(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadSbomCorrelation>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(confidence::catalog(&tx).await?))
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
        (status = 422, description = "Correlation capability disabled"),
        (status = 200, description = "Verdict counts per SBOM", body = Vec<SbomVerdictCounts>),
        (status = 400, description = "Too many SBOMs requested"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "Insufficient permissions"),
    ),
)]
#[post("/v3/correlation/verdict-counts")]
async fn count_verdicts(
    _gate: RequireCapability<Correlation>,
    web::Json(request): web::Json<VerdictCountsRequest>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadSbomCorrelation>,
) -> Result<impl Responder, Error> {
    if request.sbom_ids.len() > MAX_VERDICT_COUNT_SBOMS {
        return Err(Error::BadRequest(format!(
            "at most {MAX_VERDICT_COUNT_SBOMS} SBOMs per request"
        )));
    }

    let tx = db.begin_read().await?;
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
    /// When true, include an explanation of how each verdict was resolved.
    #[serde(default)]
    include_explanation: bool,
    /// The provider of the component, preferring assertions from the same provider when
    /// resolving verdicts. It is only used for this query.
    provider: Option<String>,
    /// Only the matches for this vulnerability, e.g. `CVE-2024-1234`.
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
        (status = 422, description = "Correlation capability disabled"),
        (status = 200, description = "Matching advisories and vulnerabilities", body = QueryResult),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "Insufficient permissions"),
    ),
)]
#[get("/v3/correlation/query")]
async fn query_correlation(
    _gate: RequireCapability<Correlation>,
    params: web::Query<IdentifierQuery>,
    service: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadAdvisory>,
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
        (status = 422, description = "Correlation capability disabled"),
        (status = 200, description = "The statements", body = inline(trustify_common::model::PaginatedResults<AdvisoryStatement>)),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    ),
)]
#[get("/v3/correlation/advisory/{id}/statement")]
async fn list_advisory_statements(
    _gate: RequireCapability<Correlation>,
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
