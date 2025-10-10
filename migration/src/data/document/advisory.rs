use super::Document;
use bytes::Bytes;
use sea_orm::prelude::*;
use trustify_entity::advisory;
use trustify_module_storage::service::StorageBackend;

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
    type Model = advisory::Model;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Self::Model>, DbErr> {
        advisory::Entity::find().all(tx).await
    }

    async fn source<S, C>(model: &Self::Model, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        super::load(model.source_document_id, storage, tx).await
    }
}
