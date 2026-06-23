use crate::sbom::endpoints::ExternalReferenceQueryParseError;
use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::DbErr;
use trustify_auth::authenticator::error::AuthorizationError;
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
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
    #[error(transparent)]
    ExternalReferenceQuery(Box<ExternalReferenceQueryParseError>),
    #[error("Bad request: {0}")]
    BadRequest(String),
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
    #[error("unavailable")]
    Unavailable,
}

impl From<ExternalReferenceQueryParseError> for Error {
    fn from(value: ExternalReferenceQueryParseError) -> Self {
        Self::ExternalReferenceQuery(Box::new(value))
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
            Self::BadRequest(msg) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("BadRequest", msg))
            }
            Self::NotFound(msg) => {
                HttpResponse::NotFound().json(ErrorInformation::new("NotFound", msg))
            }
            Self::Ingestor(inner) => inner.error_response(),
            Self::Authorization(inner) => inner.error_response(),
            Self::ExternalReferenceQuery(inner) => inner.error_response(),
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
