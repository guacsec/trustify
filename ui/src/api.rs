use crate::model::{CorrelationResult, PaginatedResults, SbomSummary, WellKnownInfo};
use gloo_net::http::Request;
use serde::de::DeserializeOwned;
use std::fmt;

#[derive(Debug)]
pub enum ApiError {
    Network(String),
    Deserialize(String),
    Http { status: u16, message: String },
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "Network error: {msg}"),
            Self::Deserialize(msg) => write!(f, "Failed to parse response: {msg}"),
            Self::Http { status, message } => write!(f, "HTTP {status}: {message}"),
        }
    }
}

async fn fetch_json<T: DeserializeOwned>(url: &str, token: Option<&str>) -> Result<T, ApiError> {
    let mut req = Request::get(url);

    if let Some(token) = token {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }

    let response = req
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;

    if !response.ok() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::Http { status, message });
    }

    response
        .json::<T>()
        .await
        .map_err(|e| ApiError::Deserialize(e.to_string()))
}

pub async fn fetch_sboms(
    query: &str,
    offset: u64,
    limit: u64,
    token: Option<&str>,
) -> Result<PaginatedResults<SbomSummary>, ApiError> {
    let url = if query.is_empty() {
        format!("/api/v3/sbom?offset={offset}&limit={limit}")
    } else {
        let encoded: String = js_sys::encode_uri_component(query).into();
        format!("/api/v3/sbom?q={encoded}&offset={offset}&limit={limit}")
    };
    fetch_json(&url, token).await
}

pub async fn fetch_correlation(
    sbom_id: &str,
    token: Option<&str>,
) -> Result<CorrelationResult, ApiError> {
    let url = format!("/api/v3/correlation/sbom/{sbom_id}");
    fetch_json(&url, token).await
}

pub async fn fetch_well_known() -> Result<WellKnownInfo, ApiError> {
    fetch_json("/.well-known/trustify", None).await
}
