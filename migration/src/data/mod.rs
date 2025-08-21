use anyhow::{anyhow, bail};
use bytes::BytesMut;
use futures_util::stream::TryStreamExt;
use futures_util::{StreamExt, stream};
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbErr, EntityTrait, ModelTrait, TransactionTrait,
};
use sea_orm_migration::SchemaManager;
use trustify_common::id::Id;
use trustify_entity::{sbom, source_document};
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};

#[allow(clippy::large_enum_variant)]
pub enum Sbom {
    CycloneDx(serde_cyclonedx::cyclonedx::v_1_6::CycloneDx),
    Spdx(spdx_rs::models::SPDX),
}

pub trait Document: Sized + Send + Sync {
    type Model: Send;

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

pub trait DocumentProcessor {
    async fn process<D>(
        &self,
        storage: &DispatchBackend,
        f: impl Handler<D>,
    ) -> anyhow::Result<(), DbErr>
    where
        D: Document;
}

impl<'c> DocumentProcessor for SchemaManager<'c> {
    async fn process<D>(
        &self,
        storage: &DispatchBackend,
        f: impl Handler<D>,
    ) -> anyhow::Result<(), DbErr>
    where
        D: Document,
    {
        let db = self.get_connection();
        let tx = db.begin().await?;

        // TODO: soft-lock database
        // In order to prevent new documents with an old version to be created in the meantime, we
        // should soft-lock the database.

        let all = D::all(&tx).await?;

        stream::iter(all)
            .map(async |model| {
                let doc = D::source(&model, storage, &tx).await.map_err(|err| {
                    DbErr::Migration(format!("Failed to load source document: {err}"))
                })?;
                f.call(doc, model, &tx).await.map_err(|err| {
                    DbErr::Migration(format!("Failed to process document: {err}"))
                })?;

                Ok::<_, DbErr>(())
            })
            .buffer_unordered(10) // TODO: make this configurable
            .try_collect::<Vec<_>>()
            .await?;

        // TODO: soft-unlock database

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
