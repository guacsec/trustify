/// Scanner error types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("target parse error: {0}")]
    TargetParse(String),

    #[error("SBOM parse error: {0}")]
    SbomParse(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("container error: {0}")]
    Container(String),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),
}
