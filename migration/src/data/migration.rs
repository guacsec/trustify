use crate::{
    async_trait,
    data::{Document, DocumentProcessor, Handler, Options},
};
use clap::Parser;
use futures::executor::block_on;
use sea_orm::DbErr;
use sea_orm_migration::{MigrationName, MigrationTrait, SchemaManager};
use std::{ffi::OsString, ops::Deref, sync::LazyLock};
use trustify_module_storage::{config::StorageConfig, service::dispatch::DispatchBackend};

pub struct MigrationWithData {
    pub storage: DispatchBackend,
    pub options: Options,
    pub migration: Box<dyn MigrationTraitWithData>,
}

static STORAGE: LazyLock<DispatchBackend> = LazyLock::new(init_storage);
static OPTIONS: LazyLock<Options> = LazyLock::new(init_options);

#[allow(clippy::expect_used)]
fn init_storage() -> DispatchBackend {
    // create from env-vars only
    let config = StorageConfig::parse_from::<_, OsString>(vec![]);

    block_on(config.into_storage(false)).expect("task panicked")
}

fn init_options() -> Options {
    // create from env-vars only
    Options::parse_from::<_, OsString>(vec![])
}

impl MigrationWithData {
    /// Wrap a data migration, turning it into a combined schema/data migration.
    ///
    /// **NOTE:** This may panic if the storage configuration is missing.
    pub fn new(migration: Box<dyn MigrationTraitWithData>) -> Self {
        Self {
            storage: STORAGE.clone(),
            options: OPTIONS.clone(),
            migration,
        }
    }
}

impl<M> From<M> for MigrationWithData
where
    M: MigrationTraitWithData + 'static,
{
    fn from(value: M) -> Self {
        MigrationWithData::new(Box::new(value))
    }
}

pub struct SchemaDataManager<'c> {
    pub manager: &'c SchemaManager<'c>,
    storage: &'c DispatchBackend,
    options: &'c Options,
}

impl<'a> Deref for SchemaDataManager<'a> {
    type Target = SchemaManager<'a>;

    fn deref(&self) -> &Self::Target {
        self.manager
    }
}

impl<'c> SchemaDataManager<'c> {
    pub fn new(
        manager: &'c SchemaManager<'c>,
        storage: &'c DispatchBackend,
        options: &'c Options,
    ) -> Self {
        Self {
            manager,
            storage,
            options,
        }
    }

    /// Run a data migration
    pub async fn process<D, N>(&self, name: &N, f: impl Handler<D>) -> Result<(), DbErr>
    where
        D: Document,
        N: MigrationName + Send + Sync,
    {
        if self.options.skip_all {
            // we skip all migration
            return Ok(());
        }

        if self.options.skip.iter().any(|s| s == name.name()) {
            // we skip a list of migrations, and it's on the list
            return Ok(());
        }

        self.manager.process(self.storage, self.options, f).await
    }
}

#[async_trait::async_trait]
pub trait MigrationTraitWithData: MigrationName + Send + Sync {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr>;
    async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr>;
}

#[async_trait::async_trait]
impl MigrationTrait for MigrationWithData {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        MigrationTraitWithData::up(
            &*self.migration,
            &SchemaDataManager::new(manager, &self.storage, &self.options),
        )
        .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        MigrationTraitWithData::down(
            &*self.migration,
            &SchemaDataManager::new(manager, &self.storage, &self.options),
        )
        .await
    }
}

impl MigrationName for MigrationWithData {
    fn name(&self) -> &str {
        self.migration.name()
    }
}
