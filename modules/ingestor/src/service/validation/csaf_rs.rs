//! In-process [`Validator`] backend using the `csaf-rs` CSAF specification
//! validator with the official CSAF test suite.
//!
//! The validator auto-detects CSAF version (2.0 or 2.1) from the document's
//! `document.csaf_version` field and runs the configured profile (preset).

use crate::service::{
    Format,
    validation::{
        Finding, OnError, Severity, ValidationMode, ValidationOutcome, ValidationReport, Validator,
        ValidatorError, ValidatorInput, config::ValidatorConfig,
    },
};
use anyhow::anyhow;
use csaf_validator::{
    csaf::{loader::detect_version_with, raw::RawDocument},
    validation::{TestResultStatus, validate_by_preset},
};
use sea_orm::prelude::async_trait;
use std::fmt;

/// A [`Validator`] that runs the `csaf-rs` CSAF specification validator.
pub struct CsafValidator {
    name: String,
    /// The validation profile (preset) to run: `basic`, `extended`, `full`, etc.
    profile: String,
    formats: Vec<Format>,
    mode: ValidationMode,
    threshold: Severity,
    on_error: OnError,
}

impl CsafValidator {
    pub fn new(config: &ValidatorConfig) -> Self {
        Self {
            name: config.name.clone(),
            profile: config
                .profile
                .clone()
                .unwrap_or_else(|| "basic".to_string()),
            formats: config.formats.clone(),
            mode: config.mode,
            threshold: config.threshold,
            on_error: config.on_error,
        }
    }
}

impl fmt::Debug for CsafValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsafValidator")
            .field("name", &self.name)
            .field("profile", &self.profile)
            .field("formats", &self.formats)
            .field("mode", &self.mode)
            .field("threshold", &self.threshold)
            .field("on_error", &self.on_error)
            .finish()
    }
}

fn map_test_results(results: &[csaf_validator::validation::TestResult]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for test_result in results {
        match &test_result.status {
            TestResultStatus::Success | TestResultStatus::NotFound | TestResultStatus::Skipped => {}
            TestResultStatus::Failure {
                errors,
                warnings,
                infos,
            } => {
                for err in errors {
                    findings.push(Finding {
                        severity: Severity::Error,
                        message: err.message.clone(),
                        path: Some(err.instance_path.clone()),
                        rule: Some(test_result.test_id.clone()),
                    });
                }
                for warn in warnings {
                    findings.push(Finding {
                        severity: Severity::Warning,
                        message: warn.message.clone(),
                        path: Some(warn.instance_path.clone()),
                        rule: Some(test_result.test_id.clone()),
                    });
                }
                for info in infos {
                    findings.push(Finding {
                        severity: Severity::Info,
                        message: info.message.clone(),
                        path: Some(info.instance_path.clone()),
                        rule: Some(test_result.test_id.clone()),
                    });
                }
            }
        }
    }

    findings
}

#[async_trait::async_trait]
impl Validator for CsafValidator {
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

    fn applies_to(&self, format: Format) -> bool {
        self.formats
            .iter()
            .any(|configured| format.matches_hint(*configured))
    }

    async fn validate(
        &self,
        input: &ValidatorInput<'_>,
    ) -> Result<ValidationReport, ValidatorError> {
        let vd = detect_version_with(input.bytes).map_err(|err| {
            ValidatorError::Backend(anyhow!("failed to detect CSAF version: {err}"))
        })?;

        let profile = self.profile.clone();

        let result = tokio::task::spawn_blocking(move || match vd.version.as_str() {
            "2.0" => {
                use csaf_validator::schema::csaf2_0::schema::CommonSecurityAdvisoryFramework;
                let doc = RawDocument::<CommonSecurityAdvisoryFramework>::new(vd.data);
                Ok(validate_by_preset(&doc, &vd.version, &profile))
            }
            "2.1" => {
                use csaf_validator::schema::csaf2_1::schema::CommonSecurityAdvisoryFramework;
                let doc = RawDocument::<CommonSecurityAdvisoryFramework>::new(vd.data);
                Ok(validate_by_preset(&doc, &vd.version, &profile))
            }
            other => Err(anyhow!("unsupported CSAF version: {other}")),
        })
        .await
        .map_err(|err| ValidatorError::Backend(anyhow!("blocking task failed: {err}")))?
        .map_err(ValidatorError::Backend)?;

        let findings = map_test_results(&result.test_results);

        let outcome = if findings.iter().any(|f| f.severity >= self.threshold) {
            ValidationOutcome::Failed
        } else {
            ValidationOutcome::Passed
        };

        Ok(ValidationReport {
            validator: self.name.clone(),
            findings,
            outcome,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::validation::{Backend, ValidatorConfig};

    fn config(profile: Option<&str>, mode: ValidationMode) -> ValidatorConfig {
        ValidatorConfig {
            name: "test-csaf".into(),
            backend: Backend::Csaf,
            formats: vec![Format::CSAF],
            rules: Vec::new(),
            phase: None,
            profile: profile.map(String::from),
            mode,
            threshold: Severity::Error,
            on_error: OnError::Block,
        }
    }

    fn validator(profile: Option<&str>, mode: ValidationMode) -> CsafValidator {
        CsafValidator::new(&config(profile, mode))
    }

    #[tokio::test]
    async fn valid_csaf_20_document_passes() {
        let doc = serde_json::json!({
            "document": {
                "csaf_version": "2.0",
                "title": "Test Advisory",
                "category": "csaf_base",
                "publisher": {
                    "category": "coordinator",
                    "name": "Test Publisher",
                    "namespace": "https://example.com"
                },
                "tracking": {
                    "id": "TEST-2024-001",
                    "current_release_date": "2024-01-01T00:00:00Z",
                    "initial_release_date": "2024-01-01T00:00:00Z",
                    "status": "final",
                    "version": "1",
                    "revision_history": [{
                        "number": "1",
                        "date": "2024-01-01T00:00:00Z",
                        "summary": "Initial release"
                    }]
                }
            }
        });
        let bytes = serde_json::to_vec(&doc).expect("serialize");
        let v = validator(Some("basic"), ValidationMode::Verify);
        let input = ValidatorInput {
            bytes: &bytes,
            format: Format::CSAF,
        };
        let report = v.validate(&input).await.expect("validates");
        assert_eq!(report.outcome, ValidationOutcome::Passed);
    }

    #[tokio::test]
    async fn invalid_csaf_20_document_fails() {
        let doc = serde_json::json!({
            "document": {
                "csaf_version": "2.0",
                "title": "Missing fields"
            }
        });
        let bytes = serde_json::to_vec(&doc).expect("serialize");
        let v = validator(Some("basic"), ValidationMode::Verify);
        let input = ValidatorInput {
            bytes: &bytes,
            format: Format::CSAF,
        };
        let report = v.validate(&input).await.expect("validates");
        assert_eq!(report.outcome, ValidationOutcome::Failed);
        assert!(!report.findings.is_empty());
    }

    #[tokio::test]
    async fn unsupported_version_is_backend_error() {
        let doc = serde_json::json!({
            "document": {
                "csaf_version": "1.0"
            }
        });
        let bytes = serde_json::to_vec(&doc).expect("serialize");
        let v = validator(Some("basic"), ValidationMode::Report);
        let input = ValidatorInput {
            bytes: &bytes,
            format: Format::CSAF,
        };
        assert!(v.validate(&input).await.is_err());
    }

    #[tokio::test]
    async fn non_json_is_backend_error() {
        let v = validator(Some("basic"), ValidationMode::Report);
        let input = ValidatorInput {
            bytes: b"not json at all",
            format: Format::CSAF,
        };
        assert!(v.validate(&input).await.is_err());
    }

    #[test]
    fn applies_to_csaf_not_spdx() {
        let v = validator(Some("basic"), ValidationMode::Report);
        assert!(v.applies_to(Format::CSAF));
        assert!(!v.applies_to(Format::SPDX));
        assert!(!v.applies_to(Format::CycloneDX));
    }

    #[test]
    fn applies_to_advisory_category() {
        let config = ValidatorConfig {
            name: "test".into(),
            backend: Backend::Csaf,
            formats: vec![Format::Advisory],
            rules: Vec::new(),
            phase: None,
            profile: None,
            mode: ValidationMode::Report,
            threshold: Severity::Error,
            on_error: OnError::Block,
        };
        let v = CsafValidator::new(&config);
        assert!(v.applies_to(Format::CSAF));
        assert!(v.applies_to(Format::CVE));
    }

    #[test]
    fn default_profile_is_basic() {
        let v = validator(None, ValidationMode::Report);
        assert_eq!(v.profile, "basic");
    }
}
