use sea_orm::DbErr;
use trustify_common::{db::pagination_cache::LimitError, purl::PurlErr};
use trustify_entity::labels;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Purl(#[from] PurlErr),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Database(#[from] DbErr),

    #[error(transparent)]
    Semver(#[from] lenient_semver::parser::OwnedError),

    #[error(transparent)]
    Any(#[from] anyhow::Error),

    #[error("Invalid status {0}")]
    InvalidStatus(String),

    /// A full-sync replacement was asked to write an empty set, which would
    /// delete everything the source had contributed.
    #[error("refusing to replace all entries of exploit source {0:?} with an empty set")]
    EmptyExploitSet(String),

    #[error(transparent)]
    Label(#[from] labels::Error),

    #[error(transparent)]
    Limit(#[from] LimitError),
}
