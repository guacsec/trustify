use crate::model::{
    CorrelationResult, IdentifierKind, IngestResult, PaginatedResults, QueryResult, SbomSummary,
    WellKnownInfo,
};
use gloo_net::http::Request;
use serde::de::DeserializeOwned;
use std::fmt;
use trustify_api::ingest::IngestFromUrlRequest;
use trustify_client::api::types::AdvisoryDetails;

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
    let url = format!("/api/v3/correlation/sbom/{sbom_id}?include_unmatched=true");
    fetch_json(&url, token).await
}

pub async fn query_correlation(
    kind: IdentifierKind,
    value: &str,
    token: Option<&str>,
) -> Result<QueryResult, ApiError> {
    let encoded: String = js_sys::encode_uri_component(value).into();
    let url = format!(
        "/api/v3/correlation/query?kind={}&q={encoded}",
        kind.as_str()
    );
    fetch_json(&url, token).await
}

async fn post_json<B: serde::Serialize, R: DeserializeOwned>(
    url: &str,
    body: &B,
    token: Option<&str>,
) -> Result<R, ApiError> {
    let json = serde_json::to_string(body).map_err(|e| ApiError::Network(e.to_string()))?;

    let mut req = Request::post(url).header("Content-Type", "application/json");

    if let Some(token) = token {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }

    let response = req
        .body(json)
        .map_err(|e| ApiError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;

    if !response.ok() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::Http { status, message });
    }

    response
        .json::<R>()
        .await
        .map_err(|e| ApiError::Deserialize(e.to_string()))
}

pub async fn ingest_from_url(url: &str, token: Option<&str>) -> Result<IngestResult, ApiError> {
    let body = IngestFromUrlRequest {
        url: url.to_string(),
    };
    post_json("/api/v3/upload/from-url", &body, token).await
}

pub async fn upload_document(bytes: &[u8], token: Option<&str>) -> Result<IngestResult, ApiError> {
    let array = js_sys::Uint8Array::from(bytes);

    let mut req =
        Request::post("/api/v3/upload").header("Content-Type", "application/octet-stream");

    if let Some(token) = token {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }

    let response = req
        .body(array)
        .map_err(|e| ApiError::Network(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;

    if !response.ok() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::Http { status, message });
    }

    response
        .json::<IngestResult>()
        .await
        .map_err(|e| ApiError::Deserialize(e.to_string()))
}

pub async fn fetch_advisory(id: &str, token: Option<&str>) -> Result<AdvisoryDetails, ApiError> {
    let url = format!("/api/v3/advisory/urn:uuid:{id}");
    fetch_json(&url, token).await
}

pub async fn fetch_well_known() -> Result<WellKnownInfo, ApiError> {
    fetch_json("/.well-known/trustify", None).await
}
