use actix_web::web;
use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_module_analysis::service::AnalysisService;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::dispatch::DispatchBackend;
use utoipa::{IntoParams, ToSchema};

use crate::{exploit, license, organization, product, purl, sbom};
use regex::Regex;

#[derive(Clone, Debug)]
pub struct Config {
    pub sbom_upload_limit: usize,
    pub advisory_upload_limit: usize,
    pub max_group_name_length: usize,
    /// Regex patterns used to identify vendor-rebuilt PURL versions for recommendations.
    /// Each pattern must have exactly one capture group that extracts the upstream base version.
    pub recommend_patterns: Vec<Regex>,
    /// Maximum total package count (across all requested SBOMs) allowed for a single
    /// `POST /v3/recommend/report` request. Overrides `TRUSTD_RECOMMEND_REPORT_PACKAGE_LIMIT`
    /// when set explicitly. Default: 10 000.
    pub recommend_report_package_limit: u64,
}

impl Default for Config {
    fn default() -> Self {
        let env_limit = std::env::var("TRUSTD_RECOMMEND_REPORT_PACKAGE_LIMIT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000);
        Self {
            sbom_upload_limit: 0,
            advisory_upload_limit: 0,
            max_group_name_length: 0,
            recommend_patterns: vec![],
            recommend_report_package_limit: env_limit,
        }
    }
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

    crate::advisory::endpoints::configure(
        svc,
        db_rw.clone(),
        db_ro.clone(),
        config.advisory_upload_limit,
        cache.clone(),
    );
    exploit::endpoints::configure(svc, db_ro.clone(), cache.clone());
    license::endpoints::configure(svc, db_ro.clone());
    organization::endpoints::configure(svc, db_ro.clone(), cache.clone());
    purl::endpoints::configure(
        svc,
        db_ro.clone(),
        cache.clone(),
        config.recommend_patterns,
        config.recommend_report_package_limit,
    );
    product::endpoints::configure(svc, db_rw.clone(), db_ro.clone(), cache.clone());
    sbom::endpoints::configure(
        svc,
        db_rw.clone(),
        db_ro.clone(),
        config.sbom_upload_limit,
        cache.clone(),
    );
    crate::vulnerability::endpoints::configure(svc, db_ro.clone(), cache.clone());
    crate::weakness::endpoints::configure(svc, db_ro.clone(), cache.clone());
    crate::sbom_group::endpoints::configure(svc, db_rw, db_ro, config.max_group_name_length, cache);
}

#[derive(Clone, Debug, PartialEq, Eq, Default, ToSchema, serde::Deserialize, IntoParams)]
pub struct Deprecation {
    #[serde(default)]
    #[param(inline)]
    pub deprecated: trustify_module_ingestor::common::Deprecation,
}
