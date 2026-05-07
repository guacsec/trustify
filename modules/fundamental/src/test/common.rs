use trustify_common::db::pagination_cache::PaginationCache;
use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_analysis::service::AnalysisService;
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    caller_with(ctx, Config::default()).await
}

async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
) -> anyhow::Result<impl CallService + '_> {
    let analysis = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());
    call::caller(|svc| {
        configure(
            svc,
            config,
            ctx.db.clone(),
            ctx.storage.clone(),
            analysis.clone(),
            PaginationCache::for_test(),
        );
        trustify_module_analysis::endpoints::configure(svc, ctx.db.clone(), analysis);
    })
    .await
}
