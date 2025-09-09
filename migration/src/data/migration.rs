use crate::{
    async_trait,
    data::{Document, DocumentProcessor, Handler},
};
use clap::Parser;
use sea_orm::DbErr;
use sea_orm_migration::{MigrationName, MigrationTrait, SchemaManager};
use std::{ffi::OsString, sync::LazyLock};
use trustify_module_storage::{config::StorageConfig, service::dispatch::DispatchBackend};

pub struct MigrationWithData<M>
where
    M: MigrationTraitWithData,
{
    pub storage: DispatchBackend,
    pub migration: M,
}

static STORAGE: LazyLock<DispatchBackend> = LazyLock::new(init_storage);

#[allow(clippy::expect_used)]
fn init_storage() -> DispatchBackend {
    // create from env-vars only
    let config = StorageConfig::parse_from::<_, OsString>(vec![]);

    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            config
                .into_storage(false)
                .await
                .expect("Failed to create storage")
        })
    })
}

impl<M> MigrationWithData<M>
where
    M: MigrationTraitWithData,
{
    #[allow(clippy::expect_used)]
    pub fn new(migration: M) -> Self {
        Self {
            storage: STORAGE.clone(),
            migration,
        }
    }
}

impl<M> From<M> for MigrationWithData<M>
where
    M: MigrationTraitWithData,
{
    fn from(value: M) -> Self {
        MigrationWithData::new(value)
    }
}

pub struct SchemaDataManager<'c> {
    pub manager: &'c SchemaManager<'c>,
    storage: &'c DispatchBackend,
}

impl<'c> SchemaDataManager<'c> {
    pub fn new(manager: &'c SchemaManager<'c>, storage: &'c DispatchBackend) -> Self {
        Self { manager, storage }
    }

    pub async fn process<D>(&self, f: impl Handler<D>) -> Result<(), DbErr>
    where
        D: Document,
    {
        self.manager.process(self.storage, f).await
    }
}

#[async_trait::async_trait]
pub trait MigrationTraitWithData {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr>;
    async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr>;
}

#[async_trait::async_trait]
impl<M> MigrationTrait for MigrationWithData<M>
where
    M: MigrationTraitWithData + MigrationName + Send + Sync,
{
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        self.migration
            .up(&SchemaDataManager::new(manager, &self.storage))
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        self.migration
            .down(&SchemaDataManager::new(manager, &self.storage))
            .await
    }
}

impl<M> MigrationName for MigrationWithData<M>
where
    M: MigrationTraitWithData + MigrationName + Send + Sync,
{
    fn name(&self) -> &str {
        self.migration.name()
    }
}
