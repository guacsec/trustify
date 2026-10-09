use clap::Parser;
use sea_orm_migration::prelude::*;
use trustify_module_storage::config::StorageConfig;

#[tokio::main]
async fn main() {
    let storage = StorageConfig::parse()
        .into_storage(false)
        .await
        .expect("failed to initialize storage");
    cli::run_cli(migration::Migrator::new(storage, ())).await;
}
