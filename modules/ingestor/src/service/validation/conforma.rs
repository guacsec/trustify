//! Client for a long-lived Conforma `ec validate input --server` instance.

use crate::service::{
    Format,
    validation::{
        Finding, OnError, Severity, ValidationMode, ValidationOutcome, ValidationReport, Validator,
        ValidatorError, ValidatorInput,
        config::{ConformaConfig, ValidatorConfig},
    },
};
use anyhow::{Context, anyhow, ensure};
use sea_orm::prelude::async_trait;
use serde::Deserialize;
use std::{fmt, net::IpAddr, time::Duration};
use tokio::time;
use url::Url;

const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// A validator that forwards documents to a configured Conforma server.
pub struct ConformaValidator {
    name: String,
    formats: Vec<Format>,
    mode: ValidationMode,
    threshold: Severity,
    on_error: OnError,
    run_on_ingest: bool,
    timeout: Duration,
    endpoint: Url,
    client: reqwest::Client,
}

impl ConformaValidator {
    fn new(config: &ValidatorConfig, conforma: &ConformaConfig) -> anyhow::Result<Self> {
        ensure!(
            conforma.timeout_seconds > 0 && conforma.timeout_seconds <= 86_400,
            "Conforma timeout_seconds must be between 1 and 86400"
        );
        let endpoint = endpoint_url(&conforma.url)?;

        let mut client_builder = trustify_common::reqwest::ClientFactory::new()
            .new_builder()?
            .connect_timeout(Duration::from_secs(10));
        if endpoint.host_str().is_some_and(is_loopback_host) {
            client_builder = client_builder.no_proxy();
        }
        let client = client_builder.build()?;
        Ok(Self {
            name: config.name.clone(),
            formats: config.formats.clone(),
            mode: config.mode,
            threshold: config.threshold,
            on_error: config.on_error,
            run_on_ingest: config.run_on_ingest,
            timeout: Duration::from_secs(conforma.timeout_seconds),
            endpoint,
            client,
        })
    }

    async fn evaluate(
        &self,
        input: &ValidatorInput<'_>,
        content_type: &'static str,
    ) -> Result<ValidationReport, ValidatorError> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(input.bytes.to_vec())
            .send()
            .await
            .map_err(|err| ValidatorError::Backend(anyhow!("calling Conforma server: {err}")))?;
        let status = response.status();
        let bytes = read_limited_response(response).await?;
        if !status.is_success() {
            return Err(ValidatorError::Backend(anyhow!(
                "Conforma server returned HTTP {status}"
            )));
        }
        let report: ConformaReport = serde_json::from_slice(&bytes)
            .context("decoding Conforma server report")
            .map_err(ValidatorError::Backend)?;
        map_report(&self.name, report, self.threshold)
    }
}

impl fmt::Debug for ConformaValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConformaValidator")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("formats", &self.formats)
            .field("timeout", &self.timeout)
            .field("mode", &self.mode)
            .field("threshold", &self.threshold)
            .field("on_error", &self.on_error)
            .field("run_on_ingest", &self.run_on_ingest)
            .finish()
    }
}

#[async_trait::async_trait]
impl Validator for ConformaValidator {
    fn name(&self) -> &str {
        &self.name
    }

    fn mode(&self) -> ValidationMode {
        self.mode
    }

    fn threshold(&self) -> Severity {
        self.threshold
    }

    fn on_error(&self) -> OnError {
        self.on_error
    }

    fn run_on_ingest(&self) -> bool {
        self.run_on_ingest
    }

    fn applies_to(&self, format: Format) -> bool {
        self.formats
            .iter()
            .any(|configured| format.matches_hint(*configured))
    }

    async fn validate(
        &self,
        input: &ValidatorInput<'_>,
    ) -> Result<ValidationReport, ValidatorError> {
        let content_type = input_content_type(input.bytes)?;
        match time::timeout(self.timeout, self.evaluate(input, content_type)).await {
            Ok(result) => result,
            Err(_) => Err(ValidatorError::Timeout),
        }
    }
}

pub(crate) fn build(
    config: &ValidatorConfig,
    conforma: &ConformaConfig,
) -> anyhow::Result<ConformaValidator> {
    ConformaValidator::new(config, conforma)
}

fn endpoint_url(url: &str) -> anyhow::Result<Url> {
    let mut endpoint = Url::parse(url).context("parsing Conforma server URL")?;
    ensure!(
        matches!(endpoint.scheme(), "http" | "https") && endpoint.host().is_some(),
        "Conforma server URL must be an absolute HTTP(S) URL"
    );
    ensure!(
        endpoint.username().is_empty() && endpoint.password().is_none(),
        "Conforma server URL must not contain credentials"
    );
    ensure!(
        endpoint.query().is_none() && endpoint.fragment().is_none(),
        "Conforma server URL must not contain a query or fragment"
    );
    endpoint
        .path_segments_mut()
        .map_err(|_| anyhow!("Conforma server URL cannot be a base URL"))?
        .pop_if_empty()
        .extend(["v1", "validate", "input"]);
    Ok(endpoint)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn input_content_type(bytes: &[u8]) -> Result<&'static str, ValidatorError> {
    if serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok() {
        Ok("application/json")
    } else if serde_yml::from_slice::<serde::de::IgnoredAny>(bytes).is_ok() {
        Ok("application/yaml")
    } else {
        Err(ValidatorError::Backend(anyhow!(
            "Conforma input must be valid UTF-8 JSON or YAML"
        )))
    }
}

async fn read_limited_response(mut response: reqwest::Response) -> Result<Vec<u8>, ValidatorError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_REPORT_BYTES as u64)
    {
        return Err(ValidatorError::Backend(anyhow!(
            "Conforma response exceeds the {MAX_REPORT_BYTES}-byte limit"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| ValidatorError::Backend(anyhow!("reading Conforma response: {err}")))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_REPORT_BYTES {
            return Err(ValidatorError::Backend(anyhow!(
                "Conforma response exceeds the {MAX_REPORT_BYTES}-byte limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
struct ConformaReport {
    success: bool,
    #[serde(default)]
    filepaths: Vec<FileReport>,
}

#[derive(Deserialize)]
struct FileReport {
    #[serde(default)]
    violations: Vec<Diagnostic>,
    #[serde(default)]
    warnings: Vec<Diagnostic>,
}

#[derive(Deserialize)]
struct Diagnostic {
    msg: String,
    #[serde(default)]
    metadata: Option<DiagnosticMetadata>,
}

#[derive(Deserialize)]
struct DiagnosticMetadata {
    #[serde(default)]
    code: Option<String>,
}

fn map_report(
    name: &str,
    report: ConformaReport,
    threshold: Severity,
) -> Result<ValidationReport, ValidatorError> {
    if report.filepaths.is_empty() {
        return Err(ValidatorError::Backend(anyhow!(
            "Conforma report contains no file results"
        )));
    }
    let mut findings = Vec::new();
    for file in report.filepaths {
        findings.extend(file.violations.into_iter().map(|diagnostic| Finding {
            severity: Severity::Error,
            message: diagnostic.msg,
            path: None,
            rule: diagnostic.metadata.and_then(|metadata| metadata.code),
        }));
        findings.extend(file.warnings.into_iter().map(|diagnostic| Finding {
            severity: Severity::Warning,
            message: diagnostic.msg,
            path: None,
            rule: diagnostic.metadata.and_then(|metadata| metadata.code),
        }));
    }
    if !report.success
        && !findings
            .iter()
            .any(|finding| finding.severity >= Severity::Error)
    {
        findings.push(Finding {
            severity: Severity::Fatal,
            message: "Conforma reported policy failure without a blocking diagnostic".into(),
            path: None,
            rule: None,
        });
    }
    let outcome = if findings.iter().any(|finding| finding.severity >= threshold) {
        ValidationOutcome::Failed
    } else {
        ValidationOutcome::Passed
    };
    Ok(ValidationReport {
        validator: name.to_string(),
        findings,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::validation::{
        Backend, ConformaConfig, OnError, ValidatorConfig, ValidatorsConfig, validate_named,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string, header, method, path},
    };

    async fn can_connect_to_mock_server(server: &MockServer) -> bool {
        matches!(
            time::timeout(
                Duration::from_millis(250),
                tokio::net::TcpStream::connect(server.address())
            )
            .await,
            Ok(Ok(_))
        )
    }

    fn validators_config(url: String) -> ValidatorsConfig {
        ValidatorsConfig {
            validators: vec![ValidatorConfig {
                name: "conforma-test".into(),
                backend: Backend::Conforma(ConformaConfig {
                    url,
                    timeout_seconds: 5,
                }),
                formats: vec![Format::CSAF],
                run_on_ingest: false,
                mode: ValidationMode::Report,
                threshold: Severity::Error,
                on_error: OnError::Continue,
            }],
        }
    }

    #[tokio::test]
    async fn registration_posts_json_and_maps_the_conforma_verdict() {
        let server = MockServer::start().await;
        if !can_connect_to_mock_server(&server).await {
            eprintln!("skipping Conforma HTTP test: loopback sockets are unavailable");
            return;
        }
        Mock::given(method("POST"))
            .and(path("/v1/validate/input"))
            .and(header("content-type", "application/json"))
            .and(body_string(r#"{"document":true}"#))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "filepaths": [{
                    "filepath": "input.json",
                    "violations": [{"msg": "denied", "metadata": {"code": "policy.deny"}}],
                    "warnings": [{"msg": "warn"}]
                }]
            })))
            .mount(&server)
            .await;

        let url = format!("http://{}", server.address());
        let validators =
            super::super::config::build(&validators_config(url)).expect("registers Conforma");
        assert_eq!(validators.len(), 1);
        assert!(!validators[0].run_on_ingest());
        let input = ValidatorInput {
            bytes: br#"{"document":true}"#,
            format: Format::CSAF,
        };
        let result = validate_named(&validators, "conforma-test", &input).await;
        assert!(
            result.is_ok(),
            "{result:?}; requests: {:?}",
            server.received_requests().await
        );
        let report = result.expect("report checked above");
        assert_eq!(report.outcome, ValidationOutcome::Failed);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].rule.as_deref(), Some("policy.deny"));
        assert_eq!(report.findings[1].severity, Severity::Warning);
    }

    #[tokio::test]
    async fn sends_yaml_and_rejects_http_errors() {
        let server = MockServer::start().await;
        if !can_connect_to_mock_server(&server).await {
            eprintln!("skipping Conforma HTTP test: loopback sockets are unavailable");
            return;
        }
        Mock::given(method("POST"))
            .and(path("/v1/validate/input"))
            .and(header("content-type", "application/yaml"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let url = format!("http://{}", server.address());
        let validators =
            super::super::config::build(&validators_config(url)).expect("registers Conforma");
        let input = ValidatorInput {
            bytes: b"document: true\n",
            format: Format::CSAF,
        };
        let error = validate_named(&validators, "conforma-test", &input)
            .await
            .expect_err("server error is not a verdict");
        assert!(
            error.to_string().contains("HTTP 503"),
            "{error:?}; requests: {:?}",
            server.received_requests().await
        );
    }

    #[test]
    fn config_appends_endpoint_to_url_prefix() {
        let endpoint = endpoint_url("https://example.test/conforma/").expect("valid URL");
        assert_eq!(
            endpoint.as_str(),
            "https://example.test/conforma/v1/validate/input"
        );
    }

    #[test]
    fn detects_json_and_yaml_content_types() {
        assert_eq!(
            input_content_type(br#"{"document":true}"#).unwrap(),
            "application/json"
        );
        assert_eq!(
            input_content_type(b"document: true\n").unwrap(),
            "application/yaml"
        );
        assert!(input_content_type(b"\xff").is_err());
    }

    #[test]
    fn negative_report_without_violation_gets_a_fatal_finding() {
        let report = ConformaReport {
            success: false,
            filepaths: vec![FileReport {
                violations: Vec::new(),
                warnings: Vec::new(),
            }],
        };
        let report = map_report("test", report, Severity::Error).expect("maps report");
        assert_eq!(report.outcome, ValidationOutcome::Failed);
        assert_eq!(report.findings[0].severity, Severity::Fatal);
    }
}
