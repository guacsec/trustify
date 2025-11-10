use crate::{
    async_trait,
    data::{Document, DocumentProcessor, Handler, Options},
};
use clap::Parser;
use futures::executor::block_on;
use sea_orm::DbErr;
use sea_orm_migration::{MigrationName, MigrationTrait, SchemaManager};
use std::{ffi::OsString, ops::Deref, sync::LazyLock};
use tokio::task_local;
use trustify_module_storage::{config::StorageConfig, service::dispatch::DispatchBackend};

/// A migration which also processes data.
pub struct MigrationWithData {
    pub storage: DispatchBackend,
    pub options: Options,
    pub migration: Box<dyn MigrationTraitWithData>,
}

static STORAGE: LazyLock<DispatchBackend> = LazyLock::new(init_storage);
static OPTIONS: LazyLock<Options> = LazyLock::new(init_options);

task_local! {
    static TEST_STORAGE: DispatchBackend;
    static TEST_OPTIONS: Options;
}

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
        // if we have a test storage set, use this instead.
        let storage = TEST_STORAGE
            .try_with(|s| s.clone())
            .unwrap_or_else(|_| STORAGE.clone());

        let options = TEST_OPTIONS
            .try_with(|o| o.clone())
            .unwrap_or_else(|_| OPTIONS.clone());

        Self {
            storage,
            options,
            migration,
        }
    }

    /// Set a storage backend to be used for running tests.
    ///
    /// This will, for the duration of the call, initialize the migrator with the provided storage
    /// backend.
    pub async fn run_with_test<F>(
        storage: impl Into<DispatchBackend>,
        options: impl Into<Options>,
        f: F,
    ) -> F::Output
    where
        F: Future,
    {
        TEST_STORAGE
            .scope(storage.into(), async {
                TEST_OPTIONS.scope(options.into(), f).await
            })
            .await
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

/// A [`SchemaManager`], extended with data migration features.
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
        if self.options.should_skip(name.name()) {
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
        .inspect_err(|err| tracing::warn!("Migration failed: {err}"))
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
