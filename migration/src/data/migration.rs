use crate::{
    async_trait,
    data::{Document, DocumentProcessor, Handler, Options},
};
use sea_orm::{DatabaseConnection, DbErr};
use sea_orm_migration::{MigrationName, MigrationTrait, SchemaManager};
use std::ops::Deref;
use tracing::log;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// A migration which also processes data.
pub struct MigrationWithData {
    pub storage: DispatchBackend,
    pub options: Options,
    pub migration: Box<dyn MigrationTraitWithData>,
}

/// A [`SchemaManager`], extended with data migration features.
pub struct SchemaDataManager<'c> {
    pub manager: &'c SchemaManager<'c>,
    pub db: Option<&'c DatabaseConnection>,
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
        db: Option<&'c DatabaseConnection>,
        storage: &'c DispatchBackend,
        options: &'c Options,
    ) -> Self {
        log::info!("Options: {options:#?}");
        Self {
            manager,
            db,
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

        match self.db {
            Some(db) => {
                self.manager
                    .process(db, self.storage, self.options, f)
                    .await
            }
            None => {
                self.manager
                    .process(self.manager.get_connection(), self.storage, self.options, f)
                    .await
            }
        }
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
            &SchemaDataManager::new(manager, None, &self.storage, &self.options),
        )
        .await
        .inspect_err(|err| tracing::warn!("Migration failed: {err}"))
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        MigrationTraitWithData::down(
            &*self.migration,
            &SchemaDataManager::new(manager, None, &self.storage, &self.options),
        )
        .await
    }
}

impl MigrationName for MigrationWithData {
    fn name(&self) -> &str {
        self.migration.name()
    }
}
