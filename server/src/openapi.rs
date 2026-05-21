use crate::profile::api::{Config, ModuleConfig, configure, default_openapi_info};
use actix_web::App;
use trustify_common::db::{self, pagination_cache::PaginationCache};
use trustify_module_analysis::{config::AnalysisConfig, service::AnalysisService};
use trustify_module_storage::service::fs::FileSystemBackend;
use utoipa_actix_web::AppExt;

pub async fn create_openapi() -> anyhow::Result<utoipa::openapi::OpenApi> {
    let (db, _) = trustify_db::embedded::create().await?;
    let (storage, _temp) = FileSystemBackend::for_test().await?;
    let db_rw = db::ReadWrite::new(db.clone());
    let db_ro = db::ReadOnly::new(db.clone());
    let analysis = AnalysisService::new(AnalysisConfig::default(), db_ro.clone());

    let (_, mut openapi) = App::new()
        .into_utoipa_app()
        .configure(|svc| {
            configure(
                svc,
                Config {
                    config: ModuleConfig::default(),
                    db_rw,
                    db_ro,
                    cache: PaginationCache::for_test(),
                    storage: storage.into(),
                    auth: None,
                    analysis,
                    read_only: false,
                },
            );
        })
        .split_for_parts();

    openapi.info = default_openapi_info();

    Ok(openapi)
}
