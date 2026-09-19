use actix_web::{App, web};
use trustify_auth::authorizer::Authorizer;
use trustify_common::{
    db::{self, pagination_cache::PaginationCache},
    middleware::StdMiddleware,
};
use regex::Regex;
use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_ingestor::graph::Graph;
use trustify_test_context::{TrustifyContext, call::CallService};
use utoipa_actix_web::AppExt;

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    CallerBuilder::new(ctx).build().await
}

// include!'d by integration tests that don't all use every item
/// Test helper that configures the caller with `^(.+)[.-]redhat-[0-9]+$` (one capture group).
/// Matches both dot-separated (`3.0.3.redhat-00002`) and hyphen-separated (`0.14.1-redhat-00001`) vendor rebuilds.
#[allow(dead_code, clippy::expect_used)]
pub async fn caller_with_redhat_patterns(
    ctx: &TrustifyContext,
) -> anyhow::Result<impl CallService + '_> {
    caller_with(
        ctx,
        Config {
            recommend_patterns: vec![Regex::new(r"^(.+)[.-]redhat-[0-9]+$").expect("valid pattern")],
            ..Default::default()
        },
        PaginationCache::for_test(),
    )
    .await
}

pub async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
    cache: PaginationCache,
) -> anyhow::Result<impl CallService + '_> {
    CallerBuilder::new(ctx)
        .config(config)
        .pagination_cache(cache)
        .build()
        .await
}

// include!'d by integration tests that don't all use every item
#[allow(dead_code)]
pub struct CallerBuilder<'a> {
    ctx: &'a TrustifyContext,
    config: Config,
    cache: PaginationCache,
    authorizer: Authorizer,
}

// include!'d by integration tests that don't all use every item
#[allow(dead_code)]
impl<'a> CallerBuilder<'a> {
    pub fn new(ctx: &'a TrustifyContext) -> Self {
        Self {
            ctx,
            config: Config::default(),
            cache: PaginationCache::for_test(),
            authorizer: Authorizer::new(None),
        }
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn pagination_cache(mut self, cache: PaginationCache) -> Self {
        self.cache = cache;
        self
    }

    pub fn authorizer(mut self, authorizer: Authorizer) -> Self {
        self.authorizer = authorizer;
        self
    }

    pub async fn build(self) -> anyhow::Result<impl CallService + 'a> {
        let db_rw = db::ReadWrite::new(self.ctx.db.clone());
        let db_ro = db::ReadOnly::new(self.ctx.db.clone());
        let analysis = AnalysisService::new(AnalysisConfig::default(), db_ro.clone());
        let graph = Graph::new();
        let config = self.config;
        let cache = self.cache;
        let storage = self.ctx.storage.clone();

        Ok(actix_web::test::init_service(
            App::new()
                .std_middleware()
                .into_utoipa_app()
                .app_data(web::PayloadConfig::default().limit(5 * 1024 * 1024))
                .app_data(web::Data::new(self.authorizer))
                .configure(|svc| {
                    svc.service(utoipa_actix_web::scope("/api").configure(|svc| {
                        configure(svc, config, db_rw, db_ro.clone(), storage, analysis.clone(), cache, graph, Vec::new());
                        trustify_module_analysis::endpoints::configure(svc, db_ro, analysis);
                    }));
                })
                .into_app(),
        )
        .await)
    }
}
