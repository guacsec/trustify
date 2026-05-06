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

    #[error(transparent)]
    Label(#[from] labels::Error),

    #[error(transparent)]
    Limit(#[from] LimitError),
}
