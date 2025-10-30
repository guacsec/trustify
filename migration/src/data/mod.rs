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

#[allow(async_fn_in_trait)]
pub trait Handler<D>: Send
where
    D: Document,
{
    async fn call(
        &self,
        document: D,
        model: D::Model,
        tx: &DatabaseTransaction,
    ) -> anyhow::Result<()>;
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

impl Options {
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

/// A handler for data migration of documents.
#[macro_export]
macro_rules! handler {
    (async | $doc:ident: $doc_ty:ty, $model:ident, $tx:ident | $body:block) => {{
        struct H;

        impl $crate::data::Handler<$doc_ty> for H {
            async fn call(
                &self,
                $doc: $doc_ty,
                $model: <$doc_ty as $crate::data::Document>::Model,
                $tx: &sea_orm::DatabaseTransaction,
            ) -> anyhow::Result<()> {
                $body
            }
        }

        H
    }};
}

/// A handler for SBOMs.
///
/// See: [`handler!`].
#[macro_export]
macro_rules! sbom {
    (async | $doc:ident, $model:ident, $tx:ident | $body:block) => {
        $crate::handler!(async |$doc: $crate::data::Sbom, $model, $tx| $body)
    };
}

/// A handler for advisories.
///
/// See: [`handler!`].
#[macro_export]
macro_rules! advisory {
    (async | $doc:ident, $model:ident, $tx:ident | $body:block) => {
        $crate::handler!(async |$doc: $crate::data::Advisory, $model, $tx| $body)
    };
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
