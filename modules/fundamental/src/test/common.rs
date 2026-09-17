use trustify_auth::authorizer::Authorizer;
use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_analysis::service::AnalysisService;
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    CallerBuilder::new(ctx).build().await
}

// include!'d by integration tests that don't all use every item
#[allow(dead_code)]
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
        let config = self.config;
        let cache = self.cache;
        let storage = self.ctx.storage.clone();
        let authorizer = self.authorizer;

        call::caller_app(move |svc| {
            svc.app_data(actix_web::web::Data::new(authorizer));
            svc.service(utoipa_actix_web::scope("/api").configure(|svc| {
                configure(svc, config, db_rw, db_ro.clone(), storage, analysis.clone(), cache);
                trustify_module_analysis::endpoints::configure(svc, db_ro, analysis);
            }));
        })
        .await
    }
}
