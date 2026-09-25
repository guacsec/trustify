/// Errors produced by the HTTP transport layer.
pub mod error;

/// Pluggable file-discovery strategy trait and discovered-file entry type.
pub mod discovery;

mod pulp;
mod retrieval;

pub use discovery::{DiscoveredFile, DiscoveryStrategy};
pub use pulp::PulpManifest;
pub use retrieval::{sha256_hex, verify_integrity};

use crate::{
    model::{
        HttpDiscovery, HttpImporter,
        auth::{AuthMethod, CredentialConfig},
    },
    runner::{
        context::RunContext,
        progress::{Progress, ProgressInstance},
        report::{Phase, ReportBuilder, ScannerError},
    },
    server::RunOutput,
};
use error::Error as HttpError;
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Cache, Format, IngestorService},
};
use url::Url;
use walker_common::fetcher::{FetchAuthentication, Fetcher, FetcherOptions};

/// Fetch `url` using `auth_client` whose redirect policy stops at cross-host hops,
/// then re-fetch the redirect target with `plain_client` (no credentials).
/// This prevents API-key headers from being forwarded to CDN servers.
async fn fetch_file_protected(
    auth_client: &reqwest::Client,
    plain_client: &reqwest::Client,
    url: &str,
) -> Result<bytes::Bytes, walker_common::fetcher::Error> {
    let response = auth_client.get(url).send().await?;
    if response.status().is_redirection()
        && let Some(location) = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
    {
        return Ok(plain_client.get(location).send().await?.bytes().await?);
    }
    Ok(response.bytes().await?)
}

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
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor =
            IngestorService::new(Graph::new(), self.storage.clone(), self.analysis.clone());
        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let mut continuation: HashMap<String, String> =
            serde_json::from_value(continuation).unwrap_or_default();

        // Build a reqwest client, adding authentication headers when configured.
        let fetcher = build_fetcher(&http, &self.credential_config).await?;

        // For ApiKey auth, build a second pair of clients so file downloads never
        // forward the credential to CDN servers on cross-host redirects.
        let api_key_clients: Option<(reqwest::Client, reqwest::Client)> = match &http.auth {
            Some(auth) => match &auth.method {
                AuthMethod::ApiKey {
                    header,
                    value: cred,
                } => {
                    let v = cred
                        .resolve(&self.credential_config, ())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let header_name = reqwest::header::HeaderName::from_bytes(header.as_bytes())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let mut header_value = reqwest::header::HeaderValue::from_str(v.trim())
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    header_value.set_sensitive(true);

                    let mut default_headers = reqwest::header::HeaderMap::new();
                    default_headers.insert(header_name, header_value);

                    let auth_client = reqwest::Client::builder()
                        .default_headers(default_headers)
                        .redirect(reqwest::redirect::Policy::custom(|attempt| {
                            let same_origin = attempt.previous().last().map(|prev| {
                                prev.host_str() == attempt.url().host_str()
                                    && prev.port() == attempt.url().port()
                            }) == Some(true);
                            if same_origin {
                                attempt.follow()
                            } else {
                                attempt.stop()
                            }
                        }))
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    let plain_client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .map_err(|e| ScannerError::Critical(e.into()))?;
                    Some((auth_client, plain_client))
                }
                _ => None,
            },
            None => None,
        };

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

        // Start progress now that we know the file count from discovery.
        let progress = context.progress(format!("Import HTTP: {}", http.source));
        let mut progress = progress.start(files.len());

        // Inline retrieval loop — avoids requiring Send on the ingestor future.
        for file in files {
            if context.is_canceled().await {
                break;
            }
            let url_str = file.url.to_string();

            // Skip files whose SHA-256 matches the stored continuation entry —
            // they were successfully ingested on a previous run and are unchanged.
            if let Some(sha) = &file.sha256
                && continuation.get(&url_str).map(String::as_str) == Some(sha.as_str())
            {
                progress.tick().await;
                continue;
            }

            let fetch_result = if let Some((auth_client, plain_client)) = &api_key_clients {
                fetch_file_protected(auth_client, plain_client, file.url.as_str()).await
            } else {
                fetcher.fetch::<bytes::Bytes>(file.url.as_str()).await
            };
            let data = match fetch_result {
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
                Ok(_) => {
                    report.lock().tick();
                    // Record the SHA-256 so this file is skipped on the next run.
                    if let Some(sha) = file.sha256 {
                        continuation.insert(url_str, sha);
                    }
                }
                Err(err) => report
                    .lock()
                    .add_error(Phase::Upload, &url_str, err.to_string()),
            }
            progress.tick().await;
        }
        progress.finish().await;

        let report = match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build();

        Ok(RunOutput {
            report,
            continuation: serde_json::to_value(continuation).ok(),
        })
    }
}

/// Build a [`Fetcher`] for the given importer configuration.
///
/// The configured `fetch_retries` value is applied via [`FetcherOptions`] in both the
/// unauthenticated and authenticated paths, defaulting to 5 when absent. When credentials
/// are present, authentication is registered with [`FetcherOptions::authentication`] so
/// that credentials are applied per-request rather than as client-wide default headers.
async fn build_fetcher(
    http: &HttpImporter,
    credential_config: &CredentialConfig,
) -> Result<Fetcher, ScannerError> {
    let retries = http.fetch_retries.unwrap_or(5);
    let mut options = FetcherOptions::new().retries(retries);

    if let Some(auth) = &http.auth {
        let authentication = match &auth.method {
            AuthMethod::Basic { username, password } => {
                let u = username
                    .resolve(credential_config, ())
                    .map_err(|e| ScannerError::Critical(e.into()))?;
                let p = password
                    .resolve(credential_config, ())
                    .map_err(|e| ScannerError::Critical(e.into()))?;
                FetchAuthentication::Basic {
                    username: u.trim().into(),
                    password: p.trim().into(),
                }
            }
            AuthMethod::Bearer { token } => {
                let t = token
                    .resolve(credential_config, ())
                    .map_err(|e| ScannerError::Critical(e.into()))?;
                FetchAuthentication::Bearer(t.trim().into())
            }
            AuthMethod::ApiKey {
                header,
                value: cred,
            } => {
                let v = cred
                    .resolve(credential_config, ())
                    .map_err(|e| ScannerError::Critical(e.into()))?;
                FetchAuthentication::Header {
                    name: header.clone(),
                    value: v.trim().into(),
                }
            }
        };
        options = options.authentication(authentication);
    }

    Fetcher::new(options).await.map_err(ScannerError::Critical)
}

#[cfg(test)]
mod test {
    use crate::{
        model::{CommonImporter, HttpDiscovery, HttpImporter, auth::CredentialConfig},
        runner::{ImportRunner, context::RunContext},
    };
    use sha2::{Digest as _, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    /// Verifies that Basic auth username and password with trailing newlines (as produced
    /// by most editors when saving credential files) are trimmed before base64 encoding,
    /// so the correct `Authorization: Basic` header is sent.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_basic_auth_trailing_newline_is_trimmed(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use base64::{Engine as _, engine::general_purpose};
        use wiremock::matchers::header;

        // Given a mock server expecting the header encoded from trimmed credentials
        let server = MockServer::start().await;

        let expected = format!("Basic {}", general_purpose::STANDARD.encode("user:pass"));

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .and(header("authorization", expected.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        // And an importer whose username and password have trailing newlines
        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::Basic {
                username: CredentialSource::Inline("user\n".into()),
                password: CredentialSource::Inline("pass\n".into()),
            },
        });

        // When run_once_http is called
        let output = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await?;

        // Then the trimmed credentials are encoded and the run succeeds
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

    /// A [`RunContext`] that cancels after the first `is_canceled` check returns
    /// `false`. Used to test that `run_once_http` stops the file loop early.
    struct CancelAfterFirst {
        calls: AtomicUsize,
    }

    impl std::fmt::Debug for CancelAfterFirst {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CancelAfterFirst").finish()
        }
    }

    impl RunContext for CancelAfterFirst {
        fn name(&self) -> &str {
            "cancel-after-first"
        }

        async fn is_canceled(&self) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed) > 0
        }
    }

    /// Verifies that cancellation during a multi-file HTTP import stops the file
    /// loop: after `is_canceled` returns `true`, no subsequent files are fetched
    /// or ingested.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_cancellation_stops_file_loop(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        // Given a Pulp server with two files and a context that cancels after
        // the first iteration
        let server = pulp_server().await;
        let source = server.uri();

        let context = CancelAfterFirst {
            calls: AtomicUsize::new(0),
        };

        // When run_once_http is called with the cancelling context
        let output = runner(ctx)
            .run_once_http(context, importer(source), serde_json::Value::Null)
            .await?;

        // Then only the first file is ingested; the second file (bad.json) is
        // never fetched so no integrity error is recorded.
        assert_eq!(
            output.report.number_of_items, 1,
            "expected 1 item ingested before cancellation, got {}",
            output.report.number_of_items,
        );
        assert!(
            output.report.messages.is_empty(),
            "expected no errors (bad.json should not have been fetched), got {:?}",
            output.report.messages,
        );

        Ok(())
    }

    /// Verifies that `run_once_http` completes successfully when both `auth` and
    /// `fetch_retries` are configured. `fetch_retries` is honoured in the authenticated
    /// path via `FetcherOptions`, the same as in the unauthenticated path.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_honours_fetch_retries_with_auth(
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

    /// Verifies that a file whose SHA-256 is already recorded in the continuation map
    /// is not fetched on the next run: the mock server receives zero GET requests for
    /// that file path, confirming no HTTP round-trip was made.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_skips_file_with_matching_sha256_in_continuation(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        // Given a Pulp server with one valid file
        let server = MockServer::start().await;
        let body = OSV_ADVISORY.as_bytes();
        let sha = sha256(body);
        let size = body.len();
        let manifest = format!("advisory.json,{sha},{size}\n");

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

        let source = server.uri();
        let advisory_url = format!("{source}/advisory.json");

        // And a continuation that already records the file's SHA-256
        let continuation = serde_json::json!({ &advisory_url: sha });

        // When run_once_http is called with the pre-populated continuation
        let output = runner(ctx)
            .run_once_http((), importer(source), continuation)
            .await?;

        // Then the file is skipped: zero GET requests for advisory.json
        let requests = server.received_requests().await.unwrap_or_default();
        let file_requests: Vec<_> = requests
            .iter()
            .filter(|r| r.url.path() == "/advisory.json")
            .collect();
        assert_eq!(
            file_requests.len(),
            0,
            "expected 0 GET requests for advisory.json (skipped), got {}",
            file_requests.len(),
        );
        // No items ingested (skipped) and no errors
        assert_eq!(output.report.number_of_items, 0);
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that a file whose SHA-256 in the continuation map no longer matches the
    /// value declared in `PULP_MANIFEST` is re-fetched and re-ingested on the next run.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_refetches_file_with_changed_sha256(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        // Given a Pulp server with one valid file
        let server = MockServer::start().await;
        let body = OSV_ADVISORY.as_bytes();
        let sha = sha256(body);
        let size = body.len();
        let manifest = format!("advisory.json,{sha},{size}\n");

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

        let source = server.uri();
        let advisory_url = format!("{source}/advisory.json");

        // And a continuation that records a stale (different) SHA-256 for the file
        let stale_sha = "0".repeat(64);
        let continuation = serde_json::json!({ &advisory_url: stale_sha });

        // When run_once_http is called with the stale continuation
        let output = runner(ctx)
            .run_once_http((), importer(source), continuation)
            .await?;

        // Then the file is re-fetched: at least one GET request for advisory.json
        let requests = server.received_requests().await.unwrap_or_default();
        let file_requests: Vec<_> = requests
            .iter()
            .filter(|r| r.url.path() == "/advisory.json")
            .collect();
        assert!(
            !file_requests.is_empty(),
            "expected at least one GET request for advisory.json (re-fetched), got 0",
        );
        // The file is re-ingested successfully
        assert_eq!(
            output.report.number_of_items, 1,
            "expected 1 item re-ingested, got {}",
            output.report.number_of_items,
        );
        assert!(output.report.messages.is_empty());

        Ok(())
    }

    /// Verifies that the API-key header is NOT forwarded when the source server issues
    /// a cross-host redirect. The authenticated client uses a custom redirect policy
    /// that stops cross-host hops, preventing credential leakage to CDN servers.
    ///
    /// The `expect(0)` assertion on the CDN mock verifies that any request carrying the
    /// API-key header never reaches the CDN. If the header were leaked, the mock would
    /// match once, violating the expectation and causing a panic when the server is dropped.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn run_once_http_api_key_not_forwarded_on_cross_host_redirect(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};
        use wiremock::matchers::header;

        // Given a CDN server (different host) that must never receive the API-key header.
        let cdn_server = MockServer::start().await;
        // This mock matches only if x-api-key is present — expect it to match 0 times.
        Mock::given(method("GET"))
            .and(header("x-api-key", "secret"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .named("cdn-with-api-key")
            .mount(&cdn_server)
            .await;
        // Safe fallback: handle any other GET to the CDN gracefully.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"{}"))
            .mount(&cdn_server)
            .await;

        // And a Pulp source server that redirects file downloads to the CDN.
        let server = MockServer::start().await;
        let cdn_file_url = format!("{}/file.json", cdn_server.uri());

        Mock::given(method("GET"))
            .and(path("/PULP_MANIFEST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!("file.json,{sha},0\n", sha = "a".repeat(64),)),
            )
            .mount(&server)
            .await;

        // The file download redirects to the CDN (cross-host redirect).
        Mock::given(method("GET"))
            .and(path("/file.json"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", cdn_file_url.as_str()),
            )
            .mount(&server)
            .await;

        let mut imp = importer(server.uri());
        imp.auth = Some(AuthConfig {
            method: AuthMethod::ApiKey {
                header: "x-api-key".into(),
                value: CredentialSource::Inline("secret".into()),
            },
        });

        // When run_once_http is called (the result is not the focus — credential leakage is)
        let _ = runner(ctx)
            .run_once_http((), imp, serde_json::Value::Null)
            .await;

        // Then cdn_server drops here and wiremock verifies the expect(0) mock matched
        // exactly 0 times — the API-key header never reached the CDN.
        Ok(())
    }
}
