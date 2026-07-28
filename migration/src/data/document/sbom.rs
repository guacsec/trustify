use super::Document;
use bytes::Bytes;
use sea_orm::sea_query::{Expr, extension::postgres::PgExpr};
use sea_orm::{FromQueryResult, QueryFilter, QuerySelect, prelude::*};
use trustify_entity::{labels::Labels, sbom};
use trustify_module_storage::service::StorageBackend;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, FromQueryResult)]
pub struct Id {
    pub sbom: Uuid,
    pub source: Uuid,
}

#[allow(clippy::large_enum_variant)]
pub enum Sbom {
    CycloneDx(serde_cyclonedx::cyclonedx::v_1_6::CycloneDx),
    Spdx(spdx_rs::models::SPDX),
    Other(Bytes),
}

impl From<Bytes> for Sbom {
    fn from(value: Bytes) -> Self {
        serde_json::from_slice(&value)
            .map(Sbom::Spdx)
            .or_else(|_| serde_json::from_slice(&value).map(Sbom::CycloneDx))
            .unwrap_or_else(|_err| Sbom::Other(value))
    }
}

impl Document for Sbom {
    type Id = Id;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Self::Id>, DbErr> {
        sbom::Entity::find()
            .select_only()
            .column_as(sbom::Column::SourceDocumentId, "source")
            .column_as(sbom::Column::SbomId, "sbom")
            .into_model()
            .all(tx)
            .await
    }

    async fn source<S, C>(id: &Self::Id, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        super::load(id.source, storage, tx).await
    }
}

/// SPDX-only Document variant that filters `all()` to SBOMs labeled `type=spdx`.
pub struct SpdxSbom(pub Sbom);

impl From<Bytes> for SpdxSbom {
    fn from(value: Bytes) -> Self {
        SpdxSbom(Sbom::from(value))
    }
}

impl Document for SpdxSbom {
    type Id = Id;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Self::Id>, DbErr> {
        sbom::Entity::find()
            .filter(Expr::col(sbom::Column::Labels).contains(Labels::new().add("type", "spdx")))
            .select_only()
            .column_as(sbom::Column::SourceDocumentId, "source")
            .column_as(sbom::Column::SbomId, "sbom")
            .into_model()
            .all(tx)
            .await
    }

    async fn source<S, C>(id: &Self::Id, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        super::load(id.source, storage, tx).await
    }
}
