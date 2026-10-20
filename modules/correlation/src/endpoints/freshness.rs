use crate::{error::Error, model::*, service::freshness};
use actix_web::{HttpResponse, Responder, get, post, web};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::Deserialize;
use trustify_auth::{ReadAdvisory, UpdateCorrelationOption, authorizer::Require};
use trustify_common::{
    db,
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

/// A coherent snapshot prevents a freshly committed revision being attached to old results.
pub(super) async fn snapshot(tx: &sea_orm::DatabaseTransaction) -> Result<(), Error> {
    tx.execute_unprepared("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .await?;
    Ok(())
}

#[utoipa::path(tag="correlation", operation_id="getCorrelationFreshness", responses(
    (status=200, description="Freshness against matching settings", body=FreshnessOverview),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden")
))]
#[get("/v3/correlation/freshness")]
async fn overview(
    db: web::Data<db::ReadOnly>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    snapshot(&tx).await?;
    Ok(HttpResponse::Ok().json(freshness::overview(&tx).await?))
}

#[utoipa::path(tag="correlation", operation_id="listCorrelationFreshnessSboms", params(Filter, Paginated), responses(
    (status=200, description="Documents by freshness", body=inline(PaginatedResults<FreshnessDocument>)),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden")
))]
#[get("/v3/correlation/freshness/sbom")]
async fn documents(
    db: web::Data<db::ReadOnly>,
    web::Query(filter): web::Query<Filter>,
    web::Query(page): web::Query<Paginated>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    snapshot(&tx).await?;
    Ok(HttpResponse::Ok().json(freshness::documents(&tx, filter.status, page).await?))
}

#[utoipa::path(tag="correlation", operation_id="startCorrelationRefresh", responses(
    (status=202, description="Refresh queued, or existing active job", body=RefreshJob),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden"),
    (status=503, description="Write database unavailable")
))]
#[post("/v3/correlation/refresh")]
async fn start(
    db: web::Data<db::ReadWrite>,
    _: Require<UpdateCorrelationOption>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let job = freshness::start(&tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::Accepted()
        .append_header((
            "Location",
            format!("/api/v3/correlation/refresh/{}", job.id),
        ))
        .json(job))
}

#[utoipa::path(tag="correlation", operation_id="getCorrelationRefresh", params(("id"=Uuid, Path), Paginated), responses(
    (status=200, description="Refresh progress and paginated failures", body=RefreshJobDetails),
    (status=401, description="Unauthenticated"), (status=403, description="Forbidden"),
    (status=404, description="Unknown job")
))]
#[get("/v3/correlation/refresh/{id}")]
async fn get_job(
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    web::Query(page): web::Query<Paginated>,
    _: Require<ReadAdvisory>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    snapshot(&tx).await?;
    Ok(HttpResponse::Ok().json(freshness::job(&tx, *id, page).await?))
}

pub(super) fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig) {
    config
        .service(overview)
        .service(documents)
        .service(start)
        .service(get_job);
}
