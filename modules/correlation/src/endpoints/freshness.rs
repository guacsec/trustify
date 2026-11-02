use crate::{error::Error, model::*, service::freshness};
use actix_web::{HttpResponse, Responder, get, web};
use serde::Deserialize;
use trustify_auth::{ReadAdvisory, authorizer::Require};
use trustify_common::{
    capability::{Correlation, RequireCapability},
    db::{self, DatabaseExt, pagination_cache::PaginationCache},
    model::{Paginated, PaginatedResults},
};
use utoipa::IntoParams;
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
struct Filter {
    /// Omit to list all documents needing refresh.
    #[param(inline)]
    status: Option<FreshnessStatus>,
}

/// Get the correlation freshness overview
///
/// Counts SBOMs by whether their correlation evidence was extracted under the current
/// matching settings, reports ingestion extraction lag, and shows refresh jobs.
#[utoipa::path(tag="correlation-operations", operation_id="getCorrelationFreshness", responses(
    (status = 422, description = "Correlation capability disabled"),
    (status=200, description="Matching-settings freshness and background extraction lag", body=FreshnessOverview),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden")
))]
#[get("/v3/correlation/freshness")]
async fn overview(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadOnly>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(freshness::overview(&tx).await?))
}

/// List SBOMs by correlation freshness
///
/// Without a status, lists all SBOMs needing a refresh: those which are outdated or not
/// yet checked.
#[utoipa::path(tag="correlation-operations", operation_id="listCorrelationFreshnessSboms", params(Filter, Paginated), responses(
    (status = 422, description = "Correlation capability disabled"),
    (status=200, description="Documents by freshness", body=inline(PaginatedResults<FreshnessDocument>)),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden")
))]
#[get("/v3/correlation/freshness/sbom")]
async fn documents(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadOnly>,
    web::Query(filter): web::Query<Filter>,
    web::Query(page): web::Query<Paginated>,
    cache: web::Data<PaginationCache>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(freshness::documents(&tx, filter.status, page, &cache).await?))
}

/// Get a correlation refresh job
///
/// Refresh jobs are scheduled automatically whenever SBOMs have not been extracted under
/// the current matching settings. Returns the progress of the job, including an estimated
/// completion time, and a page of the SBOMs it failed to refresh.
#[utoipa::path(tag="correlation-operations", operation_id="getCorrelationRefresh", params(("id"=Uuid, Path, description="ID of the refresh job"), Paginated), responses(
    (status = 422, description = "Correlation capability disabled"),
    (status=200, description="Refresh progress and paginated failures", body=RefreshJobDetails),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden"),
    (status=404, description="Unknown job")
))]
#[get("/v3/correlation/refresh/{id}")]
async fn get_job(
    _gate: RequireCapability<Correlation>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    web::Query(page): web::Query<Paginated>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(freshness::job(&tx, *id, page).await?))
}

pub(super) fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config.service(overview).service(documents).service(get_job);
}
