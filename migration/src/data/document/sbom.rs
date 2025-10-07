use super::Document;
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use futures_util::TryStreamExt;
use sea_orm::prelude::*;
use trustify_common::id::Id;
use trustify_entity::{sbom, source_document};
use trustify_module_storage::service::{StorageBackend, StorageKey};

#[allow(clippy::large_enum_variant)]
pub enum Sbom {
    CycloneDx(serde_cyclonedx::cyclonedx::v_1_6::CycloneDx),
    Spdx(spdx_rs::models::SPDX),
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
