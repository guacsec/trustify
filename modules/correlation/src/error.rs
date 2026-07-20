use actix_web::body::BoxBody;
use actix_web::{HttpResponse, ResponseError};
use sea_orm::DbErr;
use trustify_auth::authenticator::error::AuthorizationError;
use trustify_common::db::DbError;
use trustify_common::error::ErrorInformation;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(DbErr),
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
    #[error(transparent)]
    Any(#[from] anyhow::Error),
    #[error("Correlation service not ready")]
    NotReady,
    #[error("SBOM not found: {0}")]
    SbomNotFound(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error(transparent)]
    Fundamental(trustify_module_fundamental::Error),
}

unsafe impl Send for Error {}

unsafe impl Sync for Error {}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        Self::Database(value)
    }
}

impl From<DbError> for Error {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Database(err) => Self::Database(err),
            DbError::Unavailable | DbError::ReadOnly => Self::Any(anyhow::anyhow!("{value}")),
        }
    }
}

impl From<trustify_module_fundamental::Error> for Error {
    fn from(value: trustify_module_fundamental::Error) -> Self {
        Self::Fundamental(value)
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Authorization(inner) => inner.error_response(),
            Self::NotReady => {
                HttpResponse::ServiceUnavailable().json(ErrorInformation::new("NotReady", self))
            }
            Self::SbomNotFound(id) => {
                HttpResponse::NotFound().json(ErrorInformation::new("SbomNotFound", id))
            }
            Self::BadRequest(msg) => {
                HttpResponse::BadRequest().json(ErrorInformation::new("BadRequest", msg))
            }
            err => {
                tracing::warn!("{err}");
                HttpResponse::InternalServerError().json(ErrorInformation::new("Internal", ""))
            }
        }
    }
}
