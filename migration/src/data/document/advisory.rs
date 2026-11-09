use super::Document;
use sea_orm::{FromQueryResult, QuerySelect, prelude::*};
use trustify_entity::advisory;
use trustify_module_ingestor::service::{DetectedDocument, Format};
use trustify_module_storage::service::StorageBackend;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, FromQueryResult)]
pub struct Id {
    pub advisory: Uuid,
    pub source: Uuid,
}

/// The document of an advisory: CSAF, CVE, NVD or OSV.
pub struct Advisory(pub DetectedDocument);

impl Document for Advisory {
    type Id = Id;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Self::Id>, DbErr> {
        advisory::Entity::find()
            .select_only()
            .column_as(advisory::Column::SourceDocumentId, "source")
            .column_as(advisory::Column::Id, "advisory")
            .into_model()
            .all(tx)
            .await
    }

    async fn source<S, C>(id: &Self::Id, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        super::load(id.source, Format::Advisory, storage, tx)
            .await
            .map(Self)
    }
}
