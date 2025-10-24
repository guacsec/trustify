use crate::{
    db::DatabaseExt,
    license::{
        endpoints::spdx::{get_spdx_license, list_spdx_licenses},
        service::{LicenseService, LicenseText},
    },
};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{
    db::{Database, query::Query},
    model::{Paginated, PaginatedResults},
};
use trustify_query::TrustifyQuery;
use trustify_query_derive::Query;

pub mod spdx;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let license_service = LicenseService::new();

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(license_service))
        .service(list_spdx_licenses)
        .service(get_spdx_license)
        .service(list_licenses);
}

#[allow(dead_code)]
#[derive(Query)]
struct LicenseQuery {
    license: String,
}
/// List all licenses from SBOMs
#[utoipa::path(
    operation_id = "listLicenses",
    tag = "license",
    params(
        TrustifyQuery<LicenseQuery>,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching licenses", body = PaginatedResults<LicenseText>),
    ),
)]
#[get("/v2/license")]
pub async fn list_licenses(
    service: web::Data<LicenseService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(service.licenses(search, paginated, &tx).await?))
}

#[cfg(test)]
mod test;
