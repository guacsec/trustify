#[cfg(test)]
mod test;

use crate::{
    db::DatabaseExt,
    organization::{
        model::{OrganizationDetails, OrganizationSummary},
        service::OrganizationService,
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadMetadata, authorizer::Require};
use trustify_common::{
    db::{Database, query::Query},
    model::Paginated,
};
use uuid::Uuid;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = OrganizationService::new();
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
#[get("/v2/organization")]
/// List organizations
pub async fn all(
    state: web::Data<OrganizationService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadMetadata>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
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
#[get("/v2/organization/{id}")]
/// Retrieve organization details
pub async fn get(
    state: web::Data<OrganizationService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    _: Require<ReadMetadata>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let fetched = state.fetch_organization(*id, &tx).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
