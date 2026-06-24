#[cfg(test)]
mod test;

use crate::{
    Error,
    organization::{
        model::{OrganizationDetails, OrganizationSummary},
        service::OrganizationService,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadMetadata, authorizer::Require};
use trustify_common::{
    db::{self, pagination_cache::PaginationCache, query::Query},
    model::Paginated,
};
use uuid::Uuid;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: db::ReadOnly,
    cache: PaginationCache,
) {
    let service = OrganizationService::new(cache);
    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(all)
        .service(get);
}

#[utoipa::path(
    tag = "organization",
    operation_id = "listOrganizations",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching organizations", body = OrganizationSummary),
    ),
)]
#[get("/v3/organization")]
/// List organizations
pub async fn all(
    state: web::Data<OrganizationService>,
    db: web::Data<db::ReadOnly>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadMetadata>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    Ok(HttpResponse::Ok().json(state.fetch_organizations(search, paginated, &tx).await?))
}

#[utoipa::path(
    tag = "organization",
    operation_id = "getOrganization",
    params(
        ("id", Path, description = "Opaque ID of the organization")
    ),
    responses(
        (status = 200, description = "Matching organization", body = OrganizationDetails),
        (status = 404, description = "The organization could not be found"),
    ),
)]
#[get("/v3/organization/{id}")]
/// Retrieve organization details
pub async fn get(
    state: web::Data<OrganizationService>,
    db: web::Data<db::ReadOnly>,
    id: web::Path<Uuid>,
    _: Require<ReadMetadata>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let fetched = state.fetch_organization(*id, &tx).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
