use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_analysis::service::AnalysisService;
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    caller_with(ctx, Config::default(), PaginationCache::for_test()).await
}

pub async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
    cache: PaginationCache,
) -> anyhow::Result<impl CallService + '_> {
    let analysis = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let db_ro = db::ReadOnly::new(ctx.db.clone());
    call::caller(|svc| {
        configure(
            svc,
            config,
            db_rw,
            db_ro.clone(),
            ctx.storage.clone(),
            analysis.clone(),
            cache,
        );
        trustify_module_analysis::endpoints::configure(svc, db_ro, analysis);
    })
    .await
}
