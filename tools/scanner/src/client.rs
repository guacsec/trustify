use crate::auth::OidcTokenProvider;
use crate::error::Error;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

/// Client for the trustify REST API.
pub struct TrustifyClient {
    http: Client,
    base_url: Url,
    token: Option<String>,
    oidc: Option<OidcTokenProvider>,
}

// -- Request / Response types ------------------------------------------------

/// Request body for `POST /api/v3/vulnerability/analyze`.
#[derive(Serialize)]
pub struct AnalysisRequest {
    pub purls: Vec<String>,
}

/// Top-level response from `POST /api/v3/vulnerability/analyze`.
///
/// Keys are the requested PURL strings.
pub type AnalysisResponse = BTreeMap<String, AnalysisResult>;

/// Per-PURL analysis result.
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisResult {
    #[serde(default)]
    pub details: Vec<AnalysisDetails>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// A vulnerability found for a PURL.
///
/// The v3 analyze response flattens vulnerability fields directly into
/// each details entry alongside `purl_statuses`.
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisDetails {
    pub identifier: String,
    pub title: Option<String>,
    pub base_score: Option<BaseScore>,
    #[serde(default)]
    pub purl_statuses: Vec<PurlStatus>,
}

/// CVSS base score.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseScore {
    pub score: Option<f64>,
    pub severity: Option<String>,
}

/// Status of a vulnerability from an advisory.
///
/// Each `purl_statuses` entry contains advisory info, status, scores,
/// version range, and remediations — all at the same level.
#[derive(Debug, Clone, Deserialize)]
pub struct PurlStatus {
    pub status: String,
    pub advisory: Option<AdvisoryHead>,
    #[serde(default)]
    pub scores: Vec<ScoredVector>,
    #[allow(dead_code)] // deserialized from API, used in future output formats
    pub version_range: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)] // deserialized from API, used in future output formats
    pub remediations: Vec<Remediation>,
}

/// Advisory metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryHead {
    pub identifier: String,
    #[allow(dead_code)] // deserialized from API, used in future output formats
    pub title: Option<String>,
}

/// CVSS vector with score.
#[derive(Debug, Clone, Deserialize)]
pub struct ScoredVector {
    pub score: Option<f64>,
    pub severity: Option<String>,
}

/// Remediation recommendation.
#[allow(dead_code)] // deserialized from API, used in future output formats
#[derive(Debug, Clone, Deserialize)]
pub struct Remediation {
    pub details: Option<String>,
    pub url: Option<String>,
}

// -- SBOM upload response ----------------------------------------------------

/// Response from `POST /api/v3/sbom`.
#[derive(Debug, Deserialize)]
pub struct IngestResult {
    pub id: String,
    #[allow(dead_code)] // deserialized from API, used in future output formats
    pub document_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // deserialized from API, used in future output formats
    pub warnings: Vec<String>,
}

// -- Client implementation ---------------------------------------------------

/// Maximum PURLs per analysis batch to avoid request timeouts.
const ANALYSIS_BATCH_SIZE: usize = 500;

/// Build a shared HTTP client with gzip and timeouts.
fn build_http_client() -> Client {
    Client::builder()
        .gzip(true)
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default()
}

impl TrustifyClient {
    /// Create a client with a static bearer token.
    pub fn with_token(base_url: Url, token: String) -> Self {
        Self {
            http: build_http_client(),
            base_url,
            token: Some(token),
            oidc: None,
        }
    }

    /// Create a client with an OIDC provider for dynamic tokens.
    pub fn with_oidc(base_url: Url, oidc: OidcTokenProvider) -> Self {
        Self {
            http: build_http_client(),
            base_url,
            token: None,
            oidc: Some(oidc),
        }
    }

    /// Create a client with no authentication.
    pub fn unauthenticated(base_url: Url) -> Self {
        Self {
            http: build_http_client(),
            base_url,
            token: None,
            oidc: None,
        }
    }

    /// Resolve the bearer token (static or OIDC-refreshed).
    async fn bearer_token(&self) -> Result<Option<String>, Error> {
        if let Some(t) = &self.token {
            return Ok(Some(t.clone()));
        }
        if let Some(oidc) = &self.oidc {
            return Ok(Some(oidc.get_token().await?));
        }
        Ok(None)
    }

    /// Analyze vulnerabilities for a list of PURLs.
    ///
    /// Batches large lists automatically to avoid timeouts.
    pub async fn analyze(&self, purls: &[String]) -> Result<AnalysisResponse, Error> {
        let endpoint = self.base_url.join("/api/v3/vulnerability/analyze")?;
        let mut combined = AnalysisResponse::new();

        for chunk in purls.chunks(ANALYSIS_BATCH_SIZE) {
            let body = AnalysisRequest {
                purls: chunk.to_vec(),
            };

            let mut req = self.http.post(endpoint.as_str()).json(&body);
            if let Some(token) = self.bearer_token().await? {
                req = req.bearer_auth(token);
            }

            let resp = req
                .send()
                .await?
                .error_for_status()
                .map_err(|e| Error::Api(format!("vulnerability/analyze failed: {e}")))?;

            let batch: AnalysisResponse = resp.json().await?;
            combined.extend(batch);
        }

        Ok(combined)
    }

    /// Upload an SBOM document to trustify.
    pub async fn upload_sbom(&self, sbom_json: &[u8]) -> Result<IngestResult, Error> {
        let endpoint = self.base_url.join("/api/v3/sbom")?;

        let mut req = self
            .http
            .post(endpoint.as_str())
            .header("Content-Type", "application/json")
            .body(sbom_json.to_vec());

        if let Some(token) = self.bearer_token().await? {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await?
            .error_for_status()
            .map_err(|e| Error::Api(format!("SBOM upload failed: {e}")))?;

        Ok(resp.json().await?)
    }
}
