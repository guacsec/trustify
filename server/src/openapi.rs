use crate::profile::api::{Config, ModuleConfig, configure, default_openapi_info};
use actix_web::App;
use trustify_module_analysis::{config::AnalysisConfig, service::AnalysisService};
use trustify_module_storage::service::fs::FileSystemBackend;
use utoipa_actix_web::AppExt;

pub async fn create_openapi() -> anyhow::Result<utoipa::openapi::OpenApi> {
    let (db, _) = trustify_db::embedded::create().await?;
    let (storage, _temp) = FileSystemBackend::for_test().await?;
    let analysis = AnalysisService::new(AnalysisConfig::default(), db.clone());

    let (_, mut openapi) = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            configure(
                svc,
                Config {
                    config: ModuleConfig::default(),
                    db,
                    storage: storage.into(),
                    auth: None,
                    analysis,
                    #[cfg(feature = "graphql")]
                    with_graphql: true,
                },
            );
        })
        .split_for_parts();

    openapi.info = default_openapi_info();

    Ok(openapi)
}
