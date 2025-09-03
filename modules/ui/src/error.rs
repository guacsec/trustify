use actix_web::HttpResponse;
use actix_web::body::BoxBody;
use tokio::task::JoinError;
use trustify_common::error::ErrorInformation;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Task(#[from] JoinError),
    #[error(transparent)]
    Ingestor(#[from] trustify_module_ingestor::service::Error),
    #[error("bad request: {0}")]
    BadRequest(String, Option<String>),
    #[error(transparent)]
    Decompression(#[from] trustify_common::decompress::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl actix_web::error::ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Json(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidPayload".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::BadRequest(message, details) => {
                HttpResponse::BadRequest().json(ErrorInformation {
                    error: "BadRequest".into(),
                    message: message.clone(),
                    details: details.clone(),
                })
            }
            Self::Decompression(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "Decompression".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Ingestor(err) => err.error_response(),
            err => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "InternalServerError".into(),
                message: err.to_string(),
                details: None,
            }),
        }
    }
}
