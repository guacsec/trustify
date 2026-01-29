use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::DbErr;
use std::borrow::Cow;
use trustify_common::{
    db::DatabaseErrors, decompress, error::ErrorInformation, id::IdError, purl::PurlErr,
};
use trustify_entity::labels;
use trustify_module_storage::service::StorageKeyError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IdKey(#[from] IdError),
    #[error(transparent)]
    StorageKey(#[from] StorageKeyError),
    #[error(transparent)]
    Database(DbErr),
    #[error(transparent)]
    Query(#[from] trustify_common::db::query::Error),
    #[error(transparent)]
    Ingestor(#[from] trustify_module_ingestor::service::Error),
    #[error(transparent)]
    Purl(#[from] PurlErr),
    #[error("Bad request: {0}: {1:?}")]
    BadRequest(Cow<'static, str>, Option<Cow<'static, str>>),
    #[error("Conflict: {0}")]
    Conflict(Cow<'static, str>),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("Unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error(transparent)]
    Storage(anyhow::Error),
    #[error("Invalid data model {0}")]
    Data(String),
    #[error("Internal Server Error: {0}")]
    Internal(String),
    #[error(transparent)]
    Compression(#[from] decompress::Error),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error(transparent)]
    CsvError(#[from] csv::Error),
    #[error("error from csv inner error: {0}")]
    CsvIntoInnerError(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Label(#[from] labels::Error),
    #[error("revision not found")]
    RevisionNotFound,
    #[error("unavailable")]
    Unavailable,
}

impl Error {
    pub fn bad_request(
        message: impl Into<Cow<'static, str>>,
        details: Option<impl Into<Cow<'static, str>>>,
    ) -> Self {
        Self::BadRequest(message.into(), details.map(|d| d.into()))
    }
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        if value.is_read_only() {
            Self::Unavailable
        } else {
            Self::Database(value)
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Purl(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidPurlSyntax", err))
            }
            Self::BadRequest(message, details) => {
                HttpResponse::BadRequest().json(ErrorInformation {
                    error: "BadRequest".into(),
                    message: message.to_string(),
                    details: details.as_ref().map(|d| d.to_string()),
                })
            }
            Self::Conflict(msg) => {
                HttpResponse::Conflict().json(ErrorInformation::new("Conflict", msg))
            }
            Self::RevisionNotFound => HttpResponse::PreconditionFailed()
                .json(ErrorInformation::new("RevisionNotFound", self)),
            Self::NotFound(msg) => {
                HttpResponse::NotFound().json(ErrorInformation::new("NotFound", msg))
            }
            Self::Ingestor(inner) => inner.error_response(),
            Self::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("QueryError", err))
            }
            Self::IdKey(err) => HttpResponse::BadRequest().json(ErrorInformation::new("Key", err)),
            Self::StorageKey(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("StorageKey", err))
            }
            Self::Compression(decompress::Error::UnknownType) => {
                HttpResponse::UnsupportedMediaType()
                    .json(ErrorInformation::new("UnsupportedCompression", self))
            }
            Self::Compression(decompress::Error::PayloadTooLarge) => {
                HttpResponse::PayloadTooLarge().json(ErrorInformation::new("PayloadTooLarge", self))
            }
            Self::Compression(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("CompressionError", err))
            }
            Self::Label(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("Label", err))
            }
            Self::Unavailable => {
                HttpResponse::ServiceUnavailable().json(ErrorInformation::new("Unavailable", self))
            }

            // All other cases are internal system errors that are not expected to occur.
            // They are logged and a generic error response is returned to avoid leaking
            // internal state to end users.
            err => {
                log::warn!("{err}");
                HttpResponse::InternalServerError().json(ErrorInformation::new("Internal", ""))
            }
        }
    }
}
