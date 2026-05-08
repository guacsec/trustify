use trustify_common::db;
use trustify_module_analysis::{config::AnalysisConfig, service::AnalysisService};
use trustify_module_ingestor::endpoints::{Config, configure};
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
) -> anyhow::Result<impl CallService + '_> {
    let analysis = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());
    call::caller(|svc| {
        configure(
            svc,
            config,
            db::ReadWrite::new(ctx.db.clone()),
            ctx.storage.clone(),
            Some(analysis),
        )
    })
    .await
}
