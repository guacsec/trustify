mod sbom;
pub use sbom::*;

use crate::data::Partitionable;
use sea_orm::{ConnectionTrait, DbErr};
use trustify_module_storage::service::StorageBackend;

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
