use super::Document;
use sea_orm::{
    FromQueryResult, QueryFilter, QuerySelect,
    prelude::*,
    sea_query::{Expr, extension::postgres::PgExpr},
};
use trustify_entity::{labels::Labels, sbom};
use trustify_module_ingestor::service::{DetectedDocument, Format};
use trustify_module_storage::service::StorageBackend;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, FromQueryResult)]
pub struct Id {
    pub sbom: Uuid,
    pub source: Uuid,
}

/// The document of an SBOM: SPDX, CycloneDX or ClearlyDefined.
pub struct Sbom(pub DetectedDocument);

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
        super::load(id.source, Format::SBOM, storage, tx)
            .await
            .map(Self)
    }
}

/// SPDX-only Document variant that filters `all()` to SBOMs labeled `type=spdx`.
pub struct SpdxSbom(pub Sbom);

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
        super::load(id.source, Format::SPDX, storage, tx)
            .await
            .map(|document| Self(Sbom(document)))
    }
}
