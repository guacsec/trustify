use crate::model::{
    AdvisoryStatement, CorrelationOption, CorrelationOptionData, CorrelationResult, Created,
    IdentifierKind, IngestResult, PaginatedResults, QueryResult, SbomSummary, SbomVerdictCounts,
    StatementKind, VerdictCountsRequest, WellKnownInfo,
};
use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use std::fmt;
use trustify_api::ingest::IngestFromUrlRequest;
use trustify_client::api::types::{AdvisoryDetails, AdvisorySummary};

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

/// Fetch a page of SBOMs matching a query, with the total.
pub async fn fetch_sboms(
    query: &str,
    offset: usize,
    limit: usize,
    token: Option<&str>,
) -> Result<PaginatedResults<SbomSummary>, ApiError> {
    let mut url = format!("/api/v3/sbom?offset={offset}&limit={limit}&total=true");
    if !query.is_empty() {
        let encoded: String = js_sys::encode_uri_component(query).into();
        url.push_str(&format!("&q={encoded}"));
    }
    fetch_json(&url, token).await
}

pub async fn fetch_correlation(
    sbom_id: &str,
    token: Option<&str>,
) -> Result<CorrelationResult, ApiError> {
    let url = format!("/api/v3/correlation/sbom/{sbom_id}?include_unmatched=true");
    fetch_json(&url, token).await
}

pub async fn count_verdicts(
    sbom_ids: Vec<uuid::Uuid>,
    token: Option<&str>,
) -> Result<Vec<SbomVerdictCounts>, ApiError> {
    post_json(
        "/api/v3/correlation/verdict-counts",
        &VerdictCountsRequest { sbom_ids },
        token,
    )
    .await
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

    // No content type: a declared type disables the server's detection of compressed
    // content (xz, gzip, bzip2) by magic bytes.
    let mut req = Request::post("/api/v3/upload");

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

/// Fetch a page of advisories matching a query, with the total, optionally sorted, e.g. by
/// `published:desc`.
pub async fn fetch_advisories(
    query: &str,
    sort: Option<&str>,
    offset: usize,
    limit: usize,
    token: Option<&str>,
) -> Result<PaginatedResults<AdvisorySummary>, ApiError> {
    let mut url = format!("/api/v3/advisory?offset={offset}&limit={limit}&total=true");
    if !query.is_empty() {
        let encoded: String = js_sys::encode_uri_component(query).into();
        url.push_str(&format!("&q={encoded}"));
    }
    if let Some(sort) = sort {
        let encoded: String = js_sys::encode_uri_component(sort).into();
        url.push_str(&format!("&sort={encoded}"));
    }
    fetch_json(&url, token).await
}

pub async fn fetch_advisory(id: &str, token: Option<&str>) -> Result<AdvisoryDetails, ApiError> {
    let url = format!("/api/v3/advisory/urn:uuid:{id}");
    fetch_json(&url, token).await
}

/// Fetch the source document of an advisory, as stored at ingestion time.
pub async fn fetch_advisory_document(id: &str, token: Option<&str>) -> Result<String, ApiError> {
    let url = format!("/api/v3/advisory/urn:uuid:{id}/download");
    send(Request::get(&url), None, token)
        .await?
        .text()
        .await
        .map_err(|e| ApiError::Deserialize(e.to_string()))
}

/// Fetch a page of the statuses an advisory states for a vulnerability, about one kind of
/// subject, with the total.
pub async fn fetch_advisory_statements(
    advisory_id: &str,
    vulnerability: &str,
    kind: StatementKind,
    offset: usize,
    limit: usize,
    token: Option<&str>,
) -> Result<PaginatedResults<AdvisoryStatement>, ApiError> {
    let vulnerability: String = js_sys::encode_uri_component(vulnerability).into();
    let url = format!(
        "/api/v3/correlation/advisory/{advisory_id}/statement?kind={}&vulnerability={vulnerability}&offset={offset}&limit={limit}&total=true",
        kind.as_str()
    );
    fetch_json(&url, token).await
}

/// Send a request, failing on a non-success status.
async fn send(
    req: RequestBuilder,
    body: Option<String>,
    token: Option<&str>,
) -> Result<Response, ApiError> {
    let req = match token {
        Some(token) => req.header("Authorization", &format!("Bearer {token}")),
        None => req,
    };

    let response = match body {
        Some(body) => {
            req.header("Content-Type", "application/json")
                .body(body)
                .map_err(|e| ApiError::Network(e.to_string()))?
                .send()
                .await
        }
        None => req.send().await,
    }
    .map_err(|e| ApiError::Network(e.to_string()))?;

    if !response.ok() {
        let status = response.status();
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError::Http { status, message });
    }

    Ok(response)
}

/// Serialize a request body.
fn json_body<B: serde::Serialize>(body: &B) -> Result<String, ApiError> {
    serde_json::to_string(body).map_err(|e| ApiError::Network(e.to_string()))
}

/// Maximum number of correlation options to list.
const MAX_OPTIONS: u64 = 1000;

pub async fn fetch_options(
    token: Option<&str>,
) -> Result<PaginatedResults<CorrelationOption>, ApiError> {
    fetch_json(
        &format!("/api/v3/correlation/option?limit={MAX_OPTIONS}"),
        token,
    )
    .await
}

pub async fn create_option(
    data: &CorrelationOptionData,
    token: Option<&str>,
) -> Result<Created, ApiError> {
    post_json("/api/v3/correlation/option", data, token).await
}

pub async fn update_option(
    id: uuid::Uuid,
    data: &CorrelationOptionData,
    token: Option<&str>,
) -> Result<(), ApiError> {
    let url = format!("/api/v3/correlation/option/{id}");
    send(Request::put(&url), Some(json_body(data)?), token).await?;
    Ok(())
}

pub async fn delete_option(id: uuid::Uuid, token: Option<&str>) -> Result<(), ApiError> {
    let url = format!("/api/v3/correlation/option/{id}");
    send(Request::delete(&url), None, token).await?;
    Ok(())
}

pub async fn fetch_well_known() -> Result<WellKnownInfo, ApiError> {
    fetch_json("/.well-known/trustify", None).await
}

pub async fn preview(
    body: &trustify_api::correlation::PreviewRequest,
    token: Option<&str>,
) -> Result<trustify_api::correlation::PreviewResult, ApiError> {
    post_json("/api/v3/correlation/preview", body, token).await
}
pub async fn provider_aliases(
    token: Option<&str>,
) -> Result<Vec<trustify_api::correlation::ProviderAlias>, ApiError> {
    fetch_json("/api/v3/correlation/provider-alias", token).await
}
pub async fn save_provider_alias(
    id: Option<uuid::Uuid>,
    data: &trustify_api::correlation::ProviderAliasData,
    token: Option<&str>,
) -> Result<(), ApiError> {
    match id {
        Some(id) => {
            send(
                Request::put(&format!("/api/v3/correlation/provider-alias/{id}")),
                Some(json_body(data)?),
                token,
            )
            .await?;
        }
        None => {
            let _: trustify_api::correlation::ProviderAlias =
                post_json("/api/v3/correlation/provider-alias", data, token).await?;
        }
    }
    Ok(())
}
pub async fn delete_provider_alias(id: uuid::Uuid, token: Option<&str>) -> Result<(), ApiError> {
    send(
        Request::delete(&format!("/api/v3/correlation/provider-alias/{id}")),
        None,
        token,
    )
    .await?;
    Ok(())
}
