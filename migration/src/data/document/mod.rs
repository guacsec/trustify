pub mod advisory;
pub mod sbom;

use crate::data::Partitionable;
use anyhow::{anyhow, bail};
use bytes::{Bytes, BytesMut};
use futures_util::TryStreamExt;
use sea_orm::{ConnectionTrait, DbErr, EntityTrait};
use trustify_common::id::Id;
use trustify_entity::source_document;
use trustify_module_storage::service::{StorageBackend, StorageKey};
use uuid::Uuid;

/// A document eligible for re-processing.
#[allow(async_fn_in_trait)]
pub trait Document: Sized + Send + Sync {
    type Id: Partitionable + Send;

    async fn all<C>(tx: &C) -> Result<Vec<Self::Id>, DbErr>
    where
        C: ConnectionTrait;

    async fn source<S, C>(id: &Self::Id, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait;
}

pub(crate) async fn load<D>(
    id: Uuid,
    storage: &(impl StorageBackend + Send + Sync),
    tx: &impl ConnectionTrait,
) -> anyhow::Result<D>
where
    D: From<Bytes>,
{
    let source = source_document::Entity::find_by_id(id).one(tx).await?;

    let Some(source) = source else {
        bail!("Missing source document entry for: {id}");
    };

    let stream = storage
        .retrieve(
            StorageKey::try_from(Id::Sha256(source.sha256))
                .map_err(|err| anyhow!("Invalid ID: {err}"))?,
        )
        .await
        .map_err(|err| anyhow!("Failed to retrieve document: {err}"))?
        .ok_or_else(|| anyhow!("Missing source document for: {id}"))?;

    stream
        .try_collect::<BytesMut>()
        .await
        .map_err(|err| anyhow!("Failed to collect bytes: {err}"))
        .map(|bytes| bytes.freeze())
        .map(|bytes| bytes.into())
}
