use actix_web::web;
use trustify_common::db::{Database, pagination_cache::PaginationCache};
use trustify_module_analysis::service::AnalysisService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::{IntoParams, ToSchema};

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    pub sbom_upload_limit: usize,
    pub advisory_upload_limit: usize,
    pub max_group_name_length: usize,
}

pub fn configure(
    svc: &mut utoipa_actix_web::service_config::ServiceConfig,
    config: Config,
    db: Database,
    storage: impl Into<DispatchBackend>,
    analysis: AnalysisService,
    cache: PaginationCache,
) {
    let ingestor_service = IngestorService::new(Graph::new(db.clone()), storage, Some(analysis));
    svc.app_data(web::Data::new(ingestor_service));

    crate::advisory::endpoints::configure(
        svc,
        db.clone(),
        config.advisory_upload_limit,
        cache.clone(),
    );
    crate::license::endpoints::configure(svc, db.clone());
    crate::organization::endpoints::configure(svc, db.clone(), cache.clone());
    crate::purl::endpoints::configure(svc, db.clone(), cache.clone());
    crate::product::endpoints::configure(svc, db.clone(), cache.clone());
    crate::sbom::endpoints::configure(svc, db.clone(), config.sbom_upload_limit, cache.clone());
    crate::vulnerability::endpoints::configure(svc, db.clone(), cache.clone());
    crate::weakness::endpoints::configure(svc, db.clone(), cache.clone());
    crate::sbom_group::endpoints::configure(svc, db, config.max_group_name_length, cache);
}

#[derive(Clone, Debug, PartialEq, Eq, Default, ToSchema, serde::Deserialize, IntoParams)]
pub struct Deprecation {
    #[serde(default)]
    #[param(inline)]
    pub deprecated: trustify_module_ingestor::common::Deprecation,
}
