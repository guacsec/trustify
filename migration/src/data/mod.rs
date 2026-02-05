mod document;
mod migration;
mod partition;
mod run;

pub use document::*;
pub use migration::*;
pub use partition::*;
pub use run::*;

use futures_util::{
    StreamExt,
    stream::{self, TryStreamExt},
};
use indicatif::{ProgressBar, ProgressStyle};
use sea_orm::{DatabaseTransaction, DbErr, TransactionTrait};
use sea_orm_migration::{MigrationTrait, SchemaManager};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use trustify_module_storage::service::dispatch::DispatchBackend;

/// A handler for processing a [`Document`] data migration.
#[allow(async_fn_in_trait)]
pub trait Handler<D>: Send
where
    D: Document,
{
    async fn call(&self, document: D, id: D::Id, tx: &DatabaseTransaction) -> anyhow::Result<()>;
}

impl<F, D> Handler<D> for F
where
    D: Document,
    for<'x> F: AsyncFn(D, D::Id, &'x DatabaseTransaction) -> anyhow::Result<()> + Send,
{
    async fn call(&self, document: D, id: D::Id, tx: &DatabaseTransaction) -> anyhow::Result<()> {
        (self)(document, id, tx).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq, clap::Parser)]
pub struct Options {
    /// Number of concurrent documents being processes
    #[arg(long, env = "MIGRATION_DATA_CONCURRENT", default_value = "5")]
    pub concurrent: NonZeroUsize,

    /// The instance number of the current runner (zero based)
    #[arg(long, env = "MIGRATION_DATA_CURRENT_RUNNER", default_value = "0")]
    pub current: u64,
    /// The total number of runners
    #[arg(long, env = "MIGRATION_DATA_TOTAL_RUNNER", default_value = "1")]
    pub total: NonZeroU64,

    /// Skip running all data migrations
    #[arg(
        long,
        env = "MIGRATION_DATA_SKIP_ALL",
        default_value_t,
        conflicts_with = "skip"
    )]
    pub skip_all: bool,

    /// Skip the provided list of data migrations
    #[arg(long, env = "MIGRATION_DATA_SKIP", conflicts_with = "skip_all")]
    pub skip: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            concurrent: unsafe { NonZeroUsize::new_unchecked(5) },
            current: 0,
            total: unsafe { NonZeroU64::new_unchecked(1) },
            skip_all: false,
            skip: vec![],
        }
    }
}

impl From<()> for Options {
    fn from(_: ()) -> Self {
        Self::default()
    }
}

impl Options {
    /// Check if we should skip a data migration. Returns `true` if it should be skipped.
    ///
    /// Skipping means that the "data" part of the migration should not be processes. The schema
    /// part still will be processes.
    pub fn should_skip(&self, name: &str) -> bool {
        if self.skip_all {
            // we skip all migration
            return true;
        }

        if self.skip.iter().any(|s| s == name) {
            // we skip a list of migrations, and it's on the list
            return true;
        }

        false
    }
}

impl From<&Options> for Partition {
    fn from(value: &Options) -> Self {
        Self {
            current: value.current,
            total: value.total,
        }
    }
}

/// A trait for processing documents using a [`Handler`].
pub trait DocumentProcessor {
    fn process<D>(
        &self,
        storage: &DispatchBackend,
        options: &Options,
        f: impl Handler<D>,
    ) -> impl Future<Output = anyhow::Result<(), DbErr>>
    where
        D: Document;
}

impl<'c> DocumentProcessor for SchemaManager<'c> {
    /// Process documents for a schema *data* migration.
    ///
    /// ## Pre-requisites
    ///
    /// The database should be maintenance mode. Meaning that the actual application should be
    /// running from a read-only clone for the time of processing.
    ///
    /// ## Partitioning
    ///
    /// This will partition documents and only process documents selected for *this* partition.
    /// The partition configuration normally comes from outside, as configuration through env-vars.
    ///
    /// This means that there may be other instances of this processor running in a different
    /// process instance. However, not touching documents of our partition.
    ///
    /// ## Transaction strategy
    ///
    /// The processor will identify all documents, filtering out all which are not part of this
    /// partition. This is done in a dedicated transaction. As the database is supposed to be in
    /// read-only mode for the running instance, this is ok as no additional documents will be
    /// created during the time of processing.
    ///
    /// Next, it is processing all found documents, in a concurrent way. Meaning, this single
    /// process instance, will process multiple documents in parallel.
    ///
    /// Each document is loaded and processed within a dedicated transaction. Commiting the
    /// transaction at the end each step and before moving on the next document.
    ///
    /// As handlers are intended to be idempotent, there's no harm in re-running them, in case
    /// things go wrong.
    ///
    /// ## Caveats
    ///
    /// However, this may lead to a situation where only a part of the documents is processed.
    /// But, this is ok, as the migration is supposed to run on a clone of the database and so the
    /// actual system is still running from the read-only clone of the original data.
    async fn process<D>(
        &self,
        storage: &DispatchBackend,
        options: &Options,
        f: impl Handler<D>,
    ) -> Result<(), DbErr>
    where
        D: Document,
    {
        let partition: Partition = options.into();
        let db = self.get_connection();

        let tx = db.begin().await?;
        let all: Vec<_> = D::all(&tx)
            .await?
            .into_iter()
            .filter(|model| partition.is_selected::<D>(model))
            .collect();
        drop(tx);

        let count = all.len();
        let pb = Arc::new(ProgressBar::new(count as u64));
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})",
            )
            .map_err(|err| DbErr::Migration(err.to_string()))?
            .progress_chars("##-"),
        );

        let pb = Some(pb);

        stream::iter(all)
            .map(async |model| {
                let tx = db.begin().await?;

                let doc = D::source(&model, storage, &tx)
                    .await
                    .inspect_err(|err| tracing::info!("Failed to load source document: {err}"))
                    .map_err(|err| {
                        DbErr::Migration(format!("Failed to load source document: {err}"))
                    })?;
                f.call(doc, model, &tx)
                    .await
                    .inspect_err(|err| tracing::info!("Failed to process document: {err}"))
                    .map_err(|err| {
                        DbErr::Migration(format!("Failed to process document: {err}"))
                    })?;

                tx.commit().await?;

                if let Some(pb) = &pb {
                    pb.inc(1);
                }

                Ok::<_, DbErr>(())
            })
            .buffer_unordered(options.concurrent.into())
            .try_collect::<Vec<_>>()
            .await?;

        if let Some(pb) = &pb {
            pb.finish_with_message("Done");
        }

        tracing::info!("Processed {count} documents");

        Ok(())
    }
}

pub trait MigratorWithData {
    fn data_migrations() -> Vec<Box<dyn MigrationTraitWithData>>;
}

#[derive(Default)]
pub struct Migrations {
    all: Vec<Migration>,
}

impl Migrations {
    /// Return only [`Migration::Data`] migrations.
    pub fn only_data(self) -> Vec<Box<dyn MigrationTraitWithData>> {
        self.into_iter()
            .filter_map(|migration| match migration {
                Migration::Normal(_) => None,
                Migration::Data(migration) => Some(migration),
            })
            .collect()
    }
}

impl Extend<Migration> for Migrations {
    fn extend<T: IntoIterator<Item = Migration>>(&mut self, iter: T) {
        self.all.extend(iter)
    }
}

impl IntoIterator for Migrations {
    type Item = Migration;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.all.into_iter()
    }
}

pub enum Migration {
    Normal(Box<dyn MigrationTrait>),
    Data(Box<dyn MigrationTraitWithData>),
}

impl Migrations {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn normal(mut self, migration: impl MigrationTrait + 'static) -> Self {
        self.all.push(Migration::Normal(Box::new(migration)));
        self
    }

    pub fn data(mut self, migration: impl MigrationTraitWithData + 'static) -> Self {
        self.all.push(Migration::Data(Box::new(migration)));
        self
    }
}
