use sea_orm::DbErr;
use tokio::task::JoinError;
use trustify_common::id::IdError;

pub mod filter;
pub mod heartbeat;
pub mod http;
pub mod processing_error;
pub mod storage;
pub mod validation;
pub mod walker;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to await the task: {0}")]
    Join(#[from] JoinError),
    #[error("failed to create the working directory: {0}")]
    WorkingDir(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Git(#[from] git2::Error),
    #[error("failed to walk files: {0}")]
    Walk(#[from] walkdir::Error),
    #[error("critical processing error: {0}")]
    Processing(#[source] anyhow::Error),
    #[error("{0} is not a relative subdirectory of the repository")]
    Path(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Oci(#[from] oci_client::errors::OciDistributionError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    HttpHeader(#[from] reqwest::header::ToStrError),
    #[error(transparent)]
    HttpHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    Id(#[from] IdError),
    #[error("operation canceled")]
    Canceled,
    #[error("failed to send heartbeat: {0}")]
    Heartbeat(#[from] DbErr),
}
