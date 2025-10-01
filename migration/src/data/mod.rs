mod migration;
mod partition;
mod run;

pub use migration::*;
pub use partition::*;
pub use run::*;

use anyhow::{anyhow, bail};
use bytes::BytesMut;
use futures_util::{
    StreamExt,
    stream::{self, TryStreamExt},
};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, ModelTrait, TransactionTrait,
};
use sea_orm_migration::{MigrationTrait, SchemaManager};
use std::num::{NonZeroU64, NonZeroUsize};
use trustify_common::id::Id;
use trustify_entity::{sbom, source_document};
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};

#[allow(clippy::large_enum_variant)]
pub enum Sbom {
    CycloneDx(serde_cyclonedx::cyclonedx::v_1_6::CycloneDx),
    Spdx(spdx_rs::models::SPDX),
}

#[allow(async_fn_in_trait)]
pub trait Document: Sized + Send + Sync {
    type Model: Partitionable + Send;

    async fn all<C>(tx: &C) -> Result<Vec<Self::Model>, DbErr>
    where
        C: ConnectionTrait;

    async fn source<S, C>(model: &Self::Model, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait;
}

impl Document for Sbom {
    type Model = sbom::Model;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Self::Model>, DbErr> {
        sbom::Entity::find().all(tx).await
    }

    async fn source<S, C>(model: &Self::Model, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        let source = model.find_related(source_document::Entity).one(tx).await?;

        let Some(source) = source else {
            bail!("Missing source document ID for SBOM: {}", model.sbom_id);
        };

        let stream = storage
            .retrieve(
                StorageKey::try_from(Id::Sha256(source.sha256))
                    .map_err(|err| anyhow!("Invalid ID: {err}"))?,
            )
            .await
            .map_err(|err| anyhow!("Failed to retrieve document: {err}"))?
            .ok_or_else(|| anyhow!("Missing source document for SBOM: {}", model.sbom_id))?;

        stream
            .try_collect::<BytesMut>()
            .await
            .map_err(|err| anyhow!("Failed to collect bytes: {err}"))
            .map(|bytes| bytes.freeze())
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map(Sbom::Spdx)
                    .or_else(|_| serde_json::from_slice(&bytes).map(Sbom::CycloneDx))
                    .map_err(|err| anyhow!("Failed to parse document: {err}"))
            })
    }
}

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

    #[arg(long, env = "MIGRATION_DATA_CURRENT_RUNNER", default_value = "0")]
    pub current: u64,
    #[arg(long, env = "MIGRATION_DATA_TOTAL_RUNNER", default_value = "1")]
    pub total: NonZeroU64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            concurrent: unsafe { NonZeroUsize::new_unchecked(5) },
            current: 0,
            total: unsafe { NonZeroU64::new_unchecked(1) },
        }
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
        let all = D::all(&tx).await?;
        drop(tx);

        stream::iter(
            all.into_iter()
                .filter(|model| partition.is_selected::<D>(model)),
        )
        .map(async |model| {
            let tx = db.begin().await?;

            let doc = D::source(&model, storage, &tx).await.map_err(|err| {
                DbErr::Migration(format!("Failed to load source document: {err}"))
            })?;
            f.call(doc, model, &tx)
                .await
                .map_err(|err| DbErr::Migration(format!("Failed to process document: {err}")))?;

            tx.commit().await?;

            Ok::<_, DbErr>(())
        })
        .buffer_unordered(options.concurrent.into())
        .try_collect::<Vec<_>>()
        .await?;

        Ok(())
    }
}

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

#[macro_export]
macro_rules! sbom {
    (async | $doc:ident, $model:ident, $tx:ident | $body:block) => {
        $crate::handler!(async |$doc: $crate::data::Sbom, $model, $tx| $body)
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
