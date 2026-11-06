mod document;
mod migration;
mod partition;
mod run;

pub use document::*;
pub use migration::*;
pub use partition::*;
pub use run::*;

use futures_util::future::BoxFuture;
use indicatif::{ProgressBar, ProgressStyle};
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, TransactionTrait};
use sea_orm_migration::MigrationTrait;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, Mutex},
    thread::available_parallelism,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tracing::log;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// A handler for processing a [`Document`] data migration.
///
/// Documents are processed on the worker threads of the runtime, so a handler is a closure which
/// doesn't borrow from its environment, and returns a sendable future:
///
/// ```ignore
/// |document: Advisory, id: Id, tx| async move { Ok(()) }.boxed()
/// ```
pub trait Handler<D>:
    for<'a> Fn(D, D::Id, &'a DatabaseTransaction) -> BoxFuture<'a, anyhow::Result<()>>
    + Send
    + Sync
    + 'static
where
    D: Document,
{
}

impl<F, D> Handler<D> for F
where
    D: Document,
    F: for<'a> Fn(D, D::Id, &'a DatabaseTransaction) -> BoxFuture<'a, anyhow::Result<()>>
        + Send
        + Sync
        + 'static,
{
}

#[derive(Clone, Debug, PartialEq, Eq, clap::Parser)]
pub struct Options {
    /// Number of concurrent documents being processed
    ///
    /// If the value is zero, use the number of logical CPUs
    #[arg(long, env = "MIGRATION_DATA_CONCURRENT", default_value = "0")]
    pub concurrent: usize,

    /// Maximum number of database connections for processing documents
    ///
    /// Each document being processed holds one connection. If the value is zero, use the number of
    /// concurrent documents.
    #[arg(long, env = "MIGRATION_DATA_MAX_CONNECTIONS", default_value = "0")]
    pub max_connections: u32,

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
    #[arg(
        long,
        env = "MIGRATION_DATA_SKIP",
        conflicts_with = "skip_all",
        value_delimiter = ','
    )]
    pub skip: Vec<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            concurrent: 0,
            max_connections: 0,
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
    /// The number of documents to process concurrently.
    pub fn effective_concurrent(&self) -> usize {
        match self.concurrent {
            // if zero, use number of logical CPUs
            0 => available_parallelism().map(NonZeroUsize::get).unwrap_or(1),
            concurrent => concurrent,
        }
    }

    /// The maximum number of database connections for processing documents.
    pub fn effective_max_connections(&self) -> u32 {
        match self.max_connections {
            0 => u32::try_from(self.effective_concurrent()).unwrap_or(u32::MAX),
            max_connections => max_connections,
        }
    }

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

/// Periodically logs processing progress at info level, throttled to a configurable interval.
struct ProgressLogger {
    total: u64,
    start: Instant,
    interval: Duration,
    last_log: Mutex<Instant>,
}

impl ProgressLogger {
    fn new(total: usize, interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            total: total as u64,
            start: now,
            interval,
            last_log: Mutex::new(now),
        }
    }

    /// Record that a unit of work completed and log rate/ETA if the interval has elapsed.
    fn tick(&self, processed: u64) {
        if let Ok(mut last) = self.last_log.try_lock() {
            if last.elapsed() < self.interval {
                return;
            }
            *last = Instant::now();

            let elapsed = self.start.elapsed().as_secs_f64();
            let rate = processed as f64 / elapsed;
            let remaining = self.total.saturating_sub(processed);
            let eta = Duration::from_secs_f64(if rate > 0.0 {
                remaining as f64 / rate
            } else {
                0.0
            });

            log::info!(
                "Progress: {processed}/{} ({rate:.1}/s, ETA: {})",
                self.total,
                humantime::format_duration(eta),
            );
        }
    }
}

/// Load and process a document, committing a dedicated transaction.
async fn process_document<D>(
    db: &impl TransactionTrait<Transaction = DatabaseTransaction>,
    storage: &DispatchBackend,
    model: D::Id,
    f: &impl Handler<D>,
) -> Result<(), DbErr>
where
    D: Document,
{
    let tx = db.begin().await?;

    let doc = D::source(&model, storage, &tx)
        .await
        .inspect_err(|err| tracing::info!("Failed to load source document: {err}"))
        .map_err(|err| DbErr::Migration(format!("Failed to load source document: {err}")))?;
    f(doc, model, &tx)
        .await
        .inspect_err(|err| tracing::info!("Failed to process document: {err}"))
        .map_err(|err| DbErr::Migration(format!("Failed to process document: {err}")))?;

    tx.commit().await
}

/// The documents of this partition.
async fn partition_documents<D>(
    db: &impl TransactionTrait<Transaction = DatabaseTransaction>,
    options: &Options,
) -> Result<Vec<D::Id>, DbErr>
where
    D: Document,
{
    let partition: Partition = options.into();

    let tx = db.begin().await?;
    Ok(D::all(&tx)
        .await?
        .into_iter()
        .filter(|model| partition.is_selected::<D>(model))
        .collect())
}

/// Reports the progress of processing documents.
struct Progress {
    bar: ProgressBar,
    logger: ProgressLogger,
}

impl Progress {
    fn new(count: usize) -> Result<Self, DbErr> {
        let bar = ProgressBar::new(count as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {human_pos}/{human_len} ({per_sec}) ({eta})",
            )
                .map_err(|err| DbErr::Migration(err.to_string()))?
                .progress_chars("#>-"),
        );
        Ok(Self {
            bar,
            logger: ProgressLogger::new(count, Duration::from_secs(60)),
        })
    }

    fn document_done(&self) {
        self.bar.inc(1);
        self.logger.tick(self.bar.position());
    }

    fn finish(&self) {
        self.bar.finish_with_message("Done");
        tracing::info!("Processed {} documents", self.bar.position());
    }
}

/// Process documents for a schema *data* migration, in parallel.
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
/// Next, it is processing all found documents, each one in its own task, so that parsing and
/// processing them runs on the worker threads of the runtime.
///
/// Each document is loaded and processed within a dedicated transaction. Commiting the
/// transaction at the end each step and before moving on the next document.
///
/// As handlers are intended to be idempotent, there's no harm in re-running them, in case
/// things go wrong.
///
/// ## Failures
///
/// The first failure fails the migration, aborting the tasks still running and rolling back their
/// documents.
///
/// ## Caveats
///
/// However, this may lead to a situation where only a part of the documents is processed.
/// But, this is ok, as the migration is supposed to run on a clone of the database and so the
/// actual system is still running from the read-only clone of the original data.
async fn process_parallel<D>(
    db: DatabaseConnection,
    storage: DispatchBackend,
    options: &Options,
    f: impl Handler<D>,
) -> Result<(), DbErr>
where
    D: Document,
{
    let documents = partition_documents::<D>(&db, options).await?;
    let progress = Progress::new(documents.len())?;

    let concurrent = options.effective_concurrent();
    log::info!("Running {concurrent} parallel operations");

    let f = Arc::new(f);
    let mut documents = documents.into_iter();
    let mut tasks = JoinSet::new();

    loop {
        while tasks.len() < concurrent {
            let Some(model) = documents.next() else {
                break;
            };
            let (db, storage, f) = (db.clone(), storage.clone(), f.clone());
            tasks.spawn(async move { process_document(&db, &storage, model, &*f).await });
        }

        let Some(result) = tasks.join_next().await else {
            break;
        };
        result.map_err(|err| DbErr::Migration(format!("Failed to run document task: {err}")))??;
        progress.document_done();
    }

    progress.finish();

    Ok(())
}

/// Process documents for a schema *data* migration, one at a time.
///
/// For a migration running in a transaction, on which everything has to take turns anyway. The
/// documents are committed together with it, so any failure rolls back all of them.
async fn process_sequential<D>(
    db: &impl TransactionTrait<Transaction = DatabaseTransaction>,
    storage: &DispatchBackend,
    options: &Options,
    f: impl Handler<D>,
) -> Result<(), DbErr>
where
    D: Document,
{
    let documents = partition_documents::<D>(db, options).await?;
    let progress = Progress::new(documents.len())?;

    for model in documents {
        process_document(db, storage, model, &f).await?;
        progress.document_done();
    }

    progress.finish();

    Ok(())
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

    /// Convert into SeaORM's `Vec<Box<dyn MigrationTrait>>`, wrapping data migrations with the
    /// provided storage backend and options.
    pub fn into_migration_vec(
        self,
        storage: DispatchBackend,
        options: Options,
    ) -> Vec<Box<dyn MigrationTrait>> {
        self.into_iter()
            .map(|migration| match migration {
                Migration::Normal(m) => m,
                Migration::Data(m) => Box::new(MigrationWithData {
                    storage: storage.clone(),
                    options: options.clone(),
                    migration: m,
                }) as Box<dyn MigrationTrait>,
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn connections_follow_the_concurrency() {
        let options = |concurrent, max_connections| Options {
            concurrent,
            max_connections,
            ..Default::default()
        };

        assert_eq!(options(16, 0).effective_max_connections(), 16);
        assert_eq!(options(16, 4).effective_max_connections(), 4);
        assert_eq!(
            options(0, 0).effective_max_connections() as usize,
            available_parallelism().map_or(1, NonZeroUsize::get)
        );
    }
}
