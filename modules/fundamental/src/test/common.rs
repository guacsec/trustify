use regex::Regex;
use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_ingestor::graph::Graph;
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    caller_with(ctx, Config::default(), PaginationCache::for_test()).await
}

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
    let db_rw = db::ReadWrite::new(ctx.db.clone());
    let db_ro = db::ReadOnly::new(ctx.db.clone());
    let analysis = AnalysisService::new(AnalysisConfig::default(), db_ro.clone());
    let graph = Graph::new();
    call::caller(|svc| {
        configure(
            svc,
            config,
            db_rw,
            db_ro.clone(),
            ctx.storage.clone(),
            analysis.clone(),
            cache,
            graph,
        );
        trustify_module_analysis::endpoints::configure(svc, db_ro, analysis);
    })
    .await
}
