use actix_http::StatusCode;
use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use cpe::uri::OwnedUri;
use sea_orm::DbErr;
use std::str::FromStr;
use trustify_common::db::{DatabaseErrors, DbError};
use trustify_common::error::ErrorInformation;
use trustify_common::id::IdError;
use trustify_common::purl::PurlErr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IdKey(#[from] IdError),
    #[error(transparent)]
    Database(DbErr),
    #[error(transparent)]
    Query(#[from] trustify_common::db::query::Error),
    #[error(transparent)]
    Purl(#[from] PurlErr),
    #[error(transparent)]
    Cpe(<OwnedUri as FromStr>::Err),
    #[error(transparent)]
    Actix(#[from] actix_web::Error),
    #[error("Invalid request {msg}")]
    BadRequest { msg: String, status: StatusCode },
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("Unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error("Invalid data model {0}")]
    Data(String),
    #[error("Internal Server Error: {0}")]
    Internal(String),
    #[error("unavailable")]
    Unavailable,
}

unsafe impl Send for Error {}

unsafe impl Sync for Error {}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        if value.is_read_only() {
            Self::Unavailable
        } else {
            Self::Database(value)
        }
    }
}

impl From<DbError> for Error {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Database(err) => Self::Database(err),
            DbError::Unavailable => Self::Unavailable,
            DbError::ReadOnly => Self::Internal(value.to_string()),
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Cpe(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidCpeSyntax", err))
            }
            Self::Purl(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("InvalidPurlSyntax", err))
            }
            Self::BadRequest { msg, status } => {
                HttpResponse::build(*status).json(ErrorInformation::new("BadRequest", msg))
            }
            Self::Query(err) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("QueryError", err))
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
