use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use sea_orm::DbErr;
use trustify_common::{
    db::{DatabaseErrors, DbError},
    error::ErrorInformation,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Database(DbErr),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unavailable")]
    Unavailable,
}

impl From<DbErr> for Error {
    fn from(err: DbErr) -> Self {
        if err.is_read_only() {
            Self::Unavailable
        } else {
            match err {
                DbErr::RecordNotFound(e) => Self::NotFound(e),
                other => Self::Database(other),
            }
        }
    }
}

impl From<DbError> for Error {
    fn from(value: DbError) -> Self {
        match value {
            DbError::Database(err) => Self::Database(err),
            DbError::Unavailable => Self::Unavailable,
            DbError::ReadOnly => Self::Unavailable,
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::NotFound(msg) => {
                HttpResponse::NotFound().json(ErrorInformation::new("NotFound", msg))
            }
            Self::Unavailable => {
                HttpResponse::ServiceUnavailable().json(ErrorInformation::new("Unavailable", self))
            }
            err => {
                tracing::warn!("{err}");
                HttpResponse::InternalServerError().json(ErrorInformation::new("Internal", ""))
            }
        }
    }
}
