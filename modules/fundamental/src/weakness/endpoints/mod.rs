use crate::{license::model::LicenseSummary, weakness::service::WeaknessService};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadWeakness, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    model::{Paginated, PaginatedResults},
};

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: db::ReadOnly,
    cache: PaginationCache,
) {
    let weakness_service = WeaknessService::new(cache);

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(weakness_service))
        .service(list_weaknesses)
        .service(get_weakness);
}

#[utoipa::path(
    tag = "weakness",
    operation_id = "listWeaknesses",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching weaknesses", body = PaginatedResults<LicenseSummary>),
    ),
)]
#[get("/v3/weakness")]
/// List weaknesses
pub async fn list_weaknesses(
    state: web::Data<WeaknessService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadWeakness>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(state.list_weaknesses(search, paginated, &tx).await?))
}

#[utoipa::path(
    tag = "weakness",
    operation_id = "getWeakness",
    responses(
        (status = 200, description = "The weakness", body = LicenseSummary),
        (status = 404, description = "The weakness could not be found"),
    ),
)]
#[get("/v3/weakness/{id}")]
/// Retrieve weakness details
pub async fn get_weakness(
    state: web::Data<WeaknessService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<String>,
    _: Require<ReadWeakness>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin().await?;
    if let Some(weakness_details) = state.get_weakness(&id, &tx).await? {
        Ok(HttpResponse::Ok().json(weakness_details))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[cfg(test)]
mod test;
