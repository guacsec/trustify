pub mod advisory;
pub mod sbom;

use crate::data::Partitionable;
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use futures_util::TryStreamExt;
use sea_orm::{ConnectionTrait, DbErr, EntityTrait};
use trustify_common::id::Id;
use trustify_entity::source_document;
use trustify_module_ingestor::service::{DetectedDocument, DocumentDetector, Format};
use trustify_module_storage::service::{StorageBackend, StorageKey};
use uuid::Uuid;

/// A document eligible for re-processing.
pub trait Document: Sized + Send + Sync + 'static {
    type Id: Partitionable + Send + Sync + 'static;

    fn all<C>(tx: &C) -> impl Future<Output = Result<Vec<Self::Id>, DbErr>> + Send
    where
        C: ConnectionTrait;

    fn source<S, C>(
        id: &Self::Id,
        storage: &S,
        tx: &C,
    ) -> impl Future<Output = Result<Self, anyhow::Error>> + Send
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait;
}

/// Load and parse the source document `id`, like ingestion does, as one of the formats of `hint`.
pub(crate) async fn load(
    id: Uuid,
    hint: Format,
    storage: &(impl StorageBackend + Send + Sync),
    tx: &impl ConnectionTrait,
) -> anyhow::Result<DetectedDocument> {
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

    let bytes = stream
        .try_collect::<BytesMut>()
        .await
        .map_err(|err| anyhow!("Failed to collect bytes: {err}"))?;

    // ingestion accepted it, so failing to parse it is a problem of this version
    DocumentDetector::detect_as(&bytes, hint)
        .map(DocumentDetector::into_document)
        .map_err(|err| anyhow!("Unable to parse source document {id}: {err}"))
}
