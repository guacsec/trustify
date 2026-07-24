#[cfg(test)]
mod test;

use crate::{hydrate, service::CorrelationService};
use actix_web::{HttpResponse, Responder, get, web};
use serde::Serialize;
use trustify_common::db;
use utoipa::ToSchema;
use uuid::Uuid;

/// Register correlation endpoints.
pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db_ro: db::ReadOnly,
    correlation: CorrelationService,
) {
    config
        .app_data(web::Data::new(db_ro))
        .app_data(web::Data::new(correlation))
        .service(correlation_status)
        .service(correlate_sbom)
        .service(correlate_sbom_advisory)
        .service(correlate_vuln);
}

/// Status of the correlation service.
#[derive(Debug, Clone, Serialize, serde::Deserialize, ToSchema)]
pub struct CorrelationStatus {
    /// Whether the advisory index is loaded.
    pub index_loaded: bool,
    /// Number of PURL status entries in the index.
    pub purl_entries: usize,
    /// Number of CPE status entries in the index.
    pub cpe_entries: usize,
    /// Number of product name entries in the index.
    pub product_entries: usize,
    /// Number of distinct vulnerabilities indexed.
    pub vulnerability_count: usize,
}

/// Get the status of the correlation engine.
#[utoipa::path(
    tag = "correlation",
    operation_id = "correlationStatus",
    responses(
        (status = 200, description = "Correlation engine status", body = CorrelationStatus),
    ),
)]
#[get("/v3/correlation/status")]
pub async fn correlation_status(
    correlation: web::Data<CorrelationService>,
) -> actix_web::Result<impl Responder> {
    let index = correlation.index();
    Ok(HttpResponse::Ok().json(CorrelationStatus {
        index_loaded: !index.by_purl.is_empty()
            || !index.by_cpe.is_empty()
            || !index.by_product_name.is_empty(),
        purl_entries: index.by_purl.values().map(|v| v.len()).sum(),
        cpe_entries: index.by_cpe.values().map(|v| v.len()).sum(),
        product_entries: index.by_product_name.values().map(|v| v.len()).sum(),
        vulnerability_count: index.by_vuln.len(),
    }))
}

/// Query parameters for the correlate endpoint.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct CorrelateParams {
    /// Status filter (e.g., "affected"). If empty, defaults to ["affected"].
    #[serde(default)]
    pub status: Vec<String>,
}

/// Lightweight correlation result for a single SBOM.
#[derive(Debug, Clone, Serialize, serde::Deserialize, ToSchema)]
pub struct CorrelationResult {
    /// Total number of matches.
    pub total_matches: usize,
    /// Distinct advisories matched.
    pub advisory_count: usize,
    /// Distinct vulnerabilities matched.
    pub vulnerability_count: usize,
    /// Matches grouped by status slug.
    pub by_status: std::collections::HashMap<String, usize>,
}

/// Correlate an SBOM against advisory status assertions.
///
/// Uses the in-memory advisory index and the graph cache for matching.
/// Returns a lightweight summary; full hydrated results will be available
/// at the existing `/v3/sbom/{id}/advisory` endpoint once the correlation
/// engine replaces the SQL path.
#[utoipa::path(
    tag = "correlation",
    operation_id = "correlateSbom",
    params(
        ("id" = Uuid, Path, description = "SBOM identifier"),
        CorrelateParams,
    ),
    responses(
        (status = 200, description = "Correlation results", body = CorrelationResult),
        (status = 404, description = "SBOM not found"),
    ),
)]
#[get("/v3/correlation/sbom/{id}")]
pub async fn correlate_sbom(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    web::Query(params): web::Query<CorrelateParams>,
) -> actix_web::Result<impl Responder> {
    let status_filter: Vec<&str> = if params.status.is_empty() {
        vec!["affected"]
    } else {
        params.status.iter().map(|s| s.as_str()).collect()
    };

    let tx = db.begin().await.map_err(actix_web::error::ErrorInternalServerError)?;
    let matches = correlation
        .correlate_sbom(*id, &status_filter, &tx)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let advisory_count = matches
        .iter()
        .map(|m| m.advisory_id)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let vulnerability_count = matches
        .iter()
        .map(|m| &m.vulnerability_id)
        .collect::<std::collections::HashSet<_>>()
        .len();

    let mut by_status: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for m in &matches {
        *by_status.entry(m.status_slug.clone()).or_default() += 1;
    }

    Ok(HttpResponse::Ok().json(CorrelationResult {
        total_matches: matches.len(),
        advisory_count,
        vulnerability_count,
        by_status,
    }))
}

/// Correlate a vulnerability against all SBOMs.
///
/// Uses the in-memory advisory index to find candidate SBOMs, then
/// verifies each candidate using the graph cache. Returns a lightweight
/// summary with matched SBOM count.
#[utoipa::path(
    tag = "correlation",
    operation_id = "correlateVulnerability",
    params(
        ("id" = String, Path, description = "Vulnerability identifier (e.g., CVE-2024-1234)"),
        CorrelateParams,
    ),
    responses(
        (status = 200, description = "Correlation results", body = VulnCorrelationResult),
    ),
)]
#[get("/v3/correlation/vulnerability/{id}")]
pub async fn correlate_vuln(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    web::Query(params): web::Query<CorrelateParams>,
) -> actix_web::Result<impl Responder> {
    let status_filter: Vec<&str> = if params.status.is_empty() {
        vec!["affected", "fixed", "under_investigation", "recommended"]
    } else {
        params.status.iter().map(|s| s.as_str()).collect()
    };

    let tx = db.begin().await.map_err(actix_web::error::ErrorInternalServerError)?;
    let matches = correlation
        .correlate_vuln(&id, &status_filter, &tx)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let sbom_count = matches
        .iter()
        .map(|m| m.sbom_id)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let advisory_count = matches
        .iter()
        .map(|m| m.advisory_id)
        .collect::<std::collections::HashSet<_>>()
        .len();

    let mut by_status: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for m in &matches {
        *by_status.entry(m.status_slug.clone()).or_default() += 1;
    }

    Ok(HttpResponse::Ok().json(VulnCorrelationResult {
        total_matches: matches.len(),
        sbom_count,
        advisory_count,
        by_status,
    }))
}

/// Lightweight vulnerability correlation result.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VulnCorrelationResult {
    /// Total number of matches across all SBOMs.
    pub total_matches: usize,
    /// Number of distinct SBOMs matched.
    pub sbom_count: usize,
    /// Number of distinct advisories matched.
    pub advisory_count: usize,
    /// Matches grouped by status slug.
    pub by_status: std::collections::HashMap<String, usize>,
}

/// Hydrated advisory result for an SBOM.
///
/// Returns the same `Vec<SbomAdvisory>` format as
/// `GET /v3/sbom/{id}/advisory`, enabling direct comparison between
/// the SQL-based and correlation-based paths.
#[utoipa::path(
    tag = "correlation",
    operation_id = "correlateSbomAdvisory",
    params(
        ("id" = Uuid, Path, description = "SBOM identifier"),
        CorrelateParams,
    ),
    responses(
        (status = 200, description = "Advisory matches (same format as /v3/sbom/{id}/advisory)"),
        (status = 404, description = "SBOM not found"),
    ),
)]
#[get("/v3/correlation/sbom/{id}/advisory")]
pub async fn correlate_sbom_advisory(
    correlation: web::Data<CorrelationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    web::Query(params): web::Query<CorrelateParams>,
) -> actix_web::Result<impl Responder> {
    let status_filter: Vec<&str> = if params.status.is_empty() {
        vec!["affected"]
    } else {
        params.status.iter().map(|s| s.as_str()).collect()
    };

    let tx = db
        .begin()
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let matches = correlation
        .correlate_sbom(*id, &status_filter, &tx)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let hydrated = hydrate::hydrate_sbom_matches(&matches, &tx)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let advisories = hydrate::to_sbom_advisories(hydrated);

    Ok(HttpResponse::Ok().json(advisories))
}
