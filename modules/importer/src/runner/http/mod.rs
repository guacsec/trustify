/// Errors produced by the HTTP transport layer.
pub mod error;

/// Pluggable file-discovery strategy trait and discovered-file entry type.
pub mod discovery;

mod pulp;
mod retrieval;

pub use discovery::{DiscoveredFile, DiscoveryStrategy};
pub use pulp::PulpManifest;
pub use retrieval::{retrieve_files, sha256_hex, verify_integrity};

use crate::{
    model::{HttpDiscovery, HttpImporter, auth::AuthMethod},
    runner::{
        context::RunContext,
        report::{Phase, ReportBuilder, ScannerError},
    },
    server::RunOutput,
};
use base64::{Engine as _, engine::general_purpose};
use error::Error as HttpError;
use parking_lot::Mutex;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Cache, Format, IngestorService},
};
use url::Url;
use walker_common::fetcher::{Fetcher, FetcherOptions};

impl super::ImportRunner {
    /// Run a single HTTP import pass.
    ///
    /// Resolves the configured discovery strategy, authenticates the HTTP client
    /// when credentials are provided, downloads and integrity-verifies each
    /// discovered file, and ingests it via the ingestor service.  Fetch or
    /// integrity errors are recorded in the run report and do not abort the
    /// remaining files.
    #[instrument(skip(self, context), err)]
    pub async fn run_once_http(
        &self,
        context: impl RunContext + 'static,
        http: HttpImporter,
        _continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor =
            IngestorService::new(Graph::new(), self.storage.clone(), self.analysis.clone());
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        // progress reporting
        let _progress = context.progress(format!("Import HTTP: {}", http.source));

        // Build a reqwest client, adding authentication headers when configured.
        let fetcher = build_fetcher(&http, &self.credential_config).await?;

        let source_url = Url::parse(&http.source).map_err(|e| ScannerError::Critical(e.into()))?;

        // Resolve the discovery strategy and enumerate files.
        let files = match http.discovery {
            HttpDiscovery::Pulp => PulpManifest::new(fetcher.clone(), http.only_patterns.clone())
                .map_err(|e| ScannerError::Critical(e.into()))?
                .discover(&source_url)
                .await
                .map_err(ScannerError::Critical)?,
        };

        let labels = http
            .common
            .labels
            .clone()
            .add("source", http.source.clone());

        // Inline retrieval loop — avoids requiring Send on the ingestor future.
        for file in files {
            let url_str = file.url.to_string();

            let data = match fetcher.fetch::<bytes::Bytes>(file.url.as_str()).await {
                Ok(b) => b,
                Err(err) => {
                    report.lock().add_error(
                        Phase::Retrieval,
                        &url_str,
                        HttpError::Fetch {
                            url: url_str.clone(),
                            source: err,
                        }
                        .to_string(),
                    );
                    continue;
                }
            };

            if let Err(err) = verify_integrity(&data, &file) {
                report
                    .lock()
                    .add_error(Phase::Validation, &url_str, err.to_string());
                continue;
            }

            let ingest_result = self
                .db
                .transaction(async |tx| {
                    ingestor
                        .ingest(
                            &data,
                            Format::Unknown,
                            labels.clone(),
                            None,
                            Cache::Skip,
                            tx,
                        )
                        .await
                })
                .await;

            match ingest_result {
                Ok(_) => report.lock().tick(),
                Err(err) => report
                    .lock()
                    .add_error(Phase::Upload, &url_str, err.to_string()),
            }
        }

        let report = match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build();

        Ok(RunOutput {
            report,
            continuation: None,
        })
    }
}

/// Build a [`Fetcher`] for the given importer configuration.
///
/// Without auth, `fetch_retries` is applied via [`FetcherOptions`].
/// With auth, default headers are installed on the underlying [`reqwest::Client`];
/// `fetch_retries` is not honoured in this path because [`walker_common::fetcher::Fetcher`]
/// does not expose a public constructor that accepts both a pre-built client and custom
/// retry settings — the default of 5 retries applies instead. A warning is logged when
/// `fetch_retries` is set alongside `auth` so operators are aware.
async fn build_fetcher(
    http: &HttpImporter,
    credential_config: &crate::model::auth::CredentialConfig,
) -> Result<Fetcher, ScannerError> {
    match &http.auth {
        None => {
            let retries = http.fetch_retries.unwrap_or(3);
            Fetcher::new(FetcherOptions::new().retries(retries))
                .await
                .map_err(ScannerError::Critical)
        }
        Some(auth) => {
            if http.fetch_retries.is_some() {
                tracing::warn!(
                    "fetch_retries is configured but cannot be applied to authenticated HTTP \
                     imports: walker_common::Fetcher does not expose a constructor accepting \
                     both a pre-built client and custom retry settings; \
                     the fetcher default (5 retries) will be used"
                );
            }
            let mut headers = HeaderMap::new();
            match &auth.method {
                AuthMethod::Basic { username, password } => {
                    let u = username
                        .resolve(credential_config, ())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let p = password
                        .resolve(credential_config, ())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let encoded = general_purpose::STANDARD.encode(format!("{u}:{p}"));
                    let value = HeaderValue::from_str(&format!("Basic {encoded}"))
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    headers.insert(AUTHORIZATION, value);
                }
                AuthMethod::Bearer { token } => {
                    let t = token
                        .resolve(credential_config, ())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let value = HeaderValue::from_str(&format!("Bearer {}", t.trim()))
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    headers.insert(AUTHORIZATION, value);
                }
                AuthMethod::ApiKey {
                    header,
                    value: cred,
                } => {
                    let v = cred
                        .resolve(credential_config, ())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let name = HeaderName::from_bytes(header.as_bytes())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let value = HeaderValue::from_str(v.trim())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    headers.insert(name, value);
                }
            }
            let client = reqwest::ClientBuilder::new()
                .timeout(Duration::from_secs(30))
                .default_headers(headers)
                .build()
                .map_err(|e| ScannerError::Critical(e.into()))?;
            Ok(Fetcher::from(client))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        model::{CommonImporter, HttpDiscovery, HttpImporter, auth::CredentialConfig},
        runner::ImportRunner,
    };
    use sha2::{Digest as _, Sha256};
    use std::time::Duration;
    use test_context::test_context;
    use test_log::test;
    use trustify_common::db::ReadWrite;
    use trustify_test_context::TrustifyContext;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const OSV_ADVISORY: &str =
        include_str!("../../../../../etc/test-data/osv/GHSA-2ccf-ffrj-m4qw.json");

    fn runner(ctx: &TrustifyContext) -> ImportRunner {
        ImportRunner {
            db: ReadWrite::new(ctx.db.clone()),
            storage: ctx.storage.clone().into(),
            working_dir: None,
            analysis: None,
            credential_config: CredentialConfig::default(),
        }
    }

    fn importer(source: impl Into<String>) -> HttpImporter {
        HttpImporter {
            common: CommonImporter {
                disabled: false,
                period: Duration::from_secs(30),
                description: None,
                labels: Default::default(),
            },
            source: source.into(),
            discovery: HttpDiscovery::Pulp,
            auth: None,
            only_patterns: vec![],
            fetch_retries: Some(0),
        }
    }

    /// Compute the lowercase hex SHA-256 of `data`.
    fn sha256(data: &[u8]) -> String {
        Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Sets up a mock server with a `PULP_MANIFEST` and two files:
    /// - `advisory.json`: a valid OSV advisory (correct SHA-256 and size)
    /// - `bad.json`: declared with an intentionally wrong SHA-256
    ///
    /// Returns the `MockServer` to keep it alive for the test duration.
    async fn pulp_server() -> MockServer {
        let server = MockServer::start().await;

        let body = OSV_ADVISORY.as_bytes();
        let sha = sha256(body);
        let size = body.len();

        let manifest = format!(
            "advisory.json,{sha},{size}\nbad.json,{bad_sha},{size}\n",
            sha = sha,
            size = size,
            bad_sha = "deadbeef".repeat(8), // 64 hex chars, wrong digest
        );

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(manifest))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/advisory.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        // The bad.json response has the correct content, but the manifest
        // declares a wrong checksum — retrieval should skip it and record an error.
        Mock::given(method("GET"))
            .and(path("/bad.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        server
    }

    /// Verifies that `run_once_http` with a Pulp discovery strategy ingests
    /// the valid advisory and records exactly one integrity error for the file
    /// with the mismatched checksum, without aborting the run.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_pulp_ingests_valid_and_skips_bad_checksum(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        // Given
        let server = pulp_server().await;
        let source = server.uri();

        let output = runner(ctx)
            .run_once_http((), importer(source), serde_json::Value::Null)
            .await?;

        // Then — exactly one file ingested, one checksum error recorded
        assert_eq!(
            output.report.number_of_items, 1,
            "expected 1 successfully processed file, got {}",
            output.report.number_of_items,
        );
        assert_eq!(
            output.report.messages.len(),
            1,
            "expected 1 error message (checksum mismatch), got {:?}",
            output.report.messages,
        );

        Ok(())
    }

    /// Verifies that `run_once_http` with `Authorization: Basic` credentials
    /// sends the correct header to the discovery and retrieval endpoints.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_basic_auth_header_is_sent(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use base64::{Engine as _, engine::general_purpose};
        use wiremock::matchers::header;

        let server = MockServer::start().await;

        let expected = format!("Basic {}", general_purpose::STANDARD.encode("user:pass"));

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .and(header("authorization", expected.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::Basic {
                username: CredentialSource::Inline("user".into()),
                password: CredentialSource::Inline("pass".into()),
            },
        });

        // An empty PULP_MANIFEST produces zero files — the run succeeds with no items.
        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that `run_once_http` with `Authorization: Bearer` credentials
    /// sends the correct header.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_bearer_auth_header_is_sent(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use wiremock::matchers::header;

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .and(header("authorization", "Bearer mytoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::Bearer {
                token: CredentialSource::Inline("mytoken".into()),
            },
        });

        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that `run_once_http` with an API-key credential sends the
    /// configured header name and value.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_api_key_header_is_sent(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use wiremock::matchers::header;

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .and(header("x-api-key", "secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::ApiKey {
                header: "x-api-key".into(),
                value: CredentialSource::Inline("secret".into()),
            },
        });

        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that `run_once_http` completes successfully when both `auth` and
    /// `fetch_retries` are configured. The warning about fetch_retries being ignored
    /// is emitted as a tracing event; run with `RUST_LOG=warn` to observe it.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_warns_when_fetch_retries_set_with_auth(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};

        // Given an importer with both auth and fetch_retries configured
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let mut imp = importer(server.uri());
        imp.fetch_retries = Some(1);
        imp.auth = Some(AuthConfig {
            method: AuthMethod::Bearer {
                token: CredentialSource::Inline("tok".into()),
            },
        });

        // When run_once_http is called
        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        // Then the run succeeds (warning is a tracing event, not an error)
        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that a Bearer token with a trailing newline (as produced by most editors
    /// when saving credential files) is trimmed before `HeaderValue::from_str`, so the
    /// run does not crash with `InvalidHeaderValue`.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_bearer_token_with_trailing_newline_is_trimmed(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use wiremock::matchers::header;

        // Given a mock server expecting the header without the trailing newline
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .and(header("authorization", "Bearer mytoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        // And an importer whose Bearer token has a trailing newline
        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::Bearer {
                token: CredentialSource::Inline("mytoken\n".into()),
            },
        });

        // When run_once_http is called
        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        // Then the trimmed token is sent and the run succeeds
        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that an API-key value with a trailing newline is trimmed before
    /// `HeaderValue::from_str`, so the run does not crash with `InvalidHeaderValue`.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_api_key_with_trailing_newline_is_trimmed(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use wiremock::matchers::header;

        // Given a mock server expecting the header without the trailing newline
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .and(header("x-api-key", "secretvalue"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        // And an importer whose API-key value has a trailing newline
        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::ApiKey {
                header: "x-api-key".into(),
                value: CredentialSource::Inline("secretvalue\n".into()),
            },
        });

        // When run_once_http is called
        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        // Then the trimmed value is sent and the run succeeds
        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }
}
