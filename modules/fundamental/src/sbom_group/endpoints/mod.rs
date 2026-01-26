use crate::sbom_group::service::SbomGroupService;
use actix_web::web;
use trustify_common::db::Database;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: Database,
    max_group_name_length: usize,
) {
    let service = SbomGroupService::new(max_group_name_length);

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service));
}
