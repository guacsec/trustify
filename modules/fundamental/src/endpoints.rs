use actix_web::web;
use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_module_analysis::service::AnalysisService;
use trustify_module_ingestor::common;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::{IntoParams, ToSchema};

use crate::{
    advisory, crypto, exploit, license, organization, product, purl, sbom, sbom_group,
    vulnerability, weakness,
};

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Config {
    pub sbom_upload_limit: usize,
    pub advisory_upload_limit: usize,
    pub max_group_name_length: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn configure(
    svc: &mut utoipa_actix_web::service_config::ServiceConfig,
    config: Config,
    db_rw: db::ReadWrite,
    db_ro: db::ReadOnly,
    storage: impl Into<DispatchBackend>,
    analysis: AnalysisService,
    cache: PaginationCache,
    graph: Graph,
) {
    let ingestor_service = IngestorService::new(graph, storage, Some(analysis));
    svc.app_data(web::Data::new(ingestor_service.clone()));

    advisory::endpoints::configure(
        svc,
        db_rw.clone(),
        db_ro.clone(),
        config.advisory_upload_limit,
        cache.clone(),
    );
    crypto::endpoints::configure(svc, db_ro.clone(), cache.clone());
    exploit::endpoints::configure(svc, db_ro.clone(), cache.clone());
    license::endpoints::configure(svc, db_ro.clone());
    organization::endpoints::configure(svc, db_ro.clone(), cache.clone());
    purl::endpoints::configure(svc, db_ro.clone(), cache.clone());
    product::endpoints::configure(svc, db_rw.clone(), db_ro.clone(), cache.clone());
    sbom::endpoints::configure(
        svc,
        db_rw.clone(),
        db_ro.clone(),
        config.sbom_upload_limit,
        cache.clone(),
    );
    vulnerability::endpoints::configure(svc, db_ro.clone(), cache.clone());
    weakness::endpoints::configure(svc, db_ro.clone(), cache.clone());
    sbom_group::endpoints::configure(svc, db_rw, db_ro, config.max_group_name_length, cache);
}

#[derive(Clone, Debug, PartialEq, Eq, Default, ToSchema, serde::Deserialize, IntoParams)]
pub struct Deprecation {
    #[serde(default)]
    #[param(inline)]
    pub deprecated: common::Deprecation,
}
