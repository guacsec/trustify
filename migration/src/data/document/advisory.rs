use super::Document;
use bytes::Bytes;
use sea_orm::{FromQueryResult, QuerySelect, prelude::*};
use trustify_entity::advisory;
use trustify_module_storage::service::StorageBackend;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, FromQueryResult)]
pub struct Id {
    pub advisory: Uuid,
    pub source: Uuid,
}

#[allow(clippy::large_enum_variant)]
pub enum Advisory {
    Cve(cve::Cve),
    Csaf(csaf::Csaf),
    Osv(osv::schema::Vulnerability),
    Other(Bytes),
}

impl From<Bytes> for Advisory {
    fn from(value: Bytes) -> Self {
        serde_json::from_slice(&value)
            .map(Advisory::Cve)
            .or_else(|_| serde_json::from_slice(&value).map(Advisory::Csaf))
            .or_else(|_| serde_json::from_slice(&value).map(Advisory::Osv))
            .unwrap_or_else(|_err| Advisory::Other(value))
    }
}

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
        super::load(id.source, storage, tx).await
    }
}
