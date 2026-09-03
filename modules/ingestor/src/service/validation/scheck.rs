//! In-process [`Validator`] backend using the [`scheck`] semantic validator.
//!
//! Rulesets are parsed once at construction; each document is validated against
//! every configured ruleset. See ADR 00020.

use crate::service::{
    Format,
    validation::{
        Finding, OnError, Severity, ValidationMode, ValidationOutcome, ValidationReport, Validator,
        ValidatorError, ValidatorInput, config::ValidatorConfig,
    },
};
use anyhow::{Context, anyhow};
use sea_orm::prelude::async_trait;
use std::{fmt, path::Path};

/// A [`Validator`] that runs one or more `scheck` rulesets in-process.
pub struct ScheckValidator {
    name: String,
    schemas: Vec<scheck::Schema>,
    /// scheck phase to activate; empty string runs all patterns.
    phase: String,
    formats: Vec<Format>,
    mode: ValidationMode,
    threshold: Severity,
    on_error: OnError,
}

impl ScheckValidator {
    /// Construct a validator from its configuration and pre-parsed rulesets.
    pub fn new(config: &ValidatorConfig, schemas: Vec<scheck::Schema>) -> Self {
        Self {
            name: config.name.clone(),
            schemas,
            phase: config.phase.clone().unwrap_or_default(),
            formats: config.formats.clone(),
            mode: config.mode,
            threshold: config.threshold,
            on_error: config.on_error,
        }
    }
}

impl fmt::Debug for ScheckValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScheckValidator")
            .field("name", &self.name)
            .field("rulesets", &self.schemas.len())
            .field("phase", &self.phase)
            .field("formats", &self.formats)
            .field("mode", &self.mode)
            .field("threshold", &self.threshold)
            .field("on_error", &self.on_error)
            .finish()
    }
}

/// Parse a ruleset from file contents, choosing the format by file extension.
///
/// Supports scheck's JSON rule format (`.json`) and its DSL (`.scheck`).
pub fn parse_ruleset(path: &Path, contents: &str) -> Result<scheck::Schema, anyhow::Error> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => serde_json::from_str(contents)
            .with_context(|| format!("parsing JSON scheck ruleset {}", path.display())),
        Some("scheck") => scheck::parse_schema(contents)
            .map_err(|err| anyhow!("parsing scheck DSL ruleset {}: {err}", path.display())),
        other => Err(anyhow!(
            "unsupported scheck ruleset extension {other:?} for {}",
            path.display()
        )),
    }
}

fn map_severity(severity: scheck::Severity) -> Severity {
    match severity {
        scheck::Severity::Info => Severity::Info,
        scheck::Severity::Warning => Severity::Warning,
        scheck::Severity::Error => Severity::Error,
        scheck::Severity::Fatal => Severity::Fatal,
    }
}

fn to_finding(result: &scheck::CheckResult) -> Finding {
    let rule = if !result.rule_id.is_empty() {
        Some(result.rule_id.clone())
    } else if !result.pattern.is_empty() {
        Some(result.pattern.clone())
    } else {
        None
    };

    Finding {
        severity: map_severity(result.severity),
        message: result.message.clone(),
        path: (!result.path.is_empty()).then(|| result.path.clone()),
        rule,
    }
}

#[async_trait::async_trait]
impl Validator for ScheckValidator {
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
        let text = std::str::from_utf8(input.bytes).map_err(|err| {
            ValidatorError::Backend(anyhow!("document is not valid UTF-8: {err}"))
        })?;
        let doc = scheck::load(text)
            .map_err(|err| ValidatorError::Backend(anyhow!("failed to load document: {err}")))?;

        let mut findings = Vec::new();
        let mut failed = false;

        for schema in &self.schemas {
            let report = scheck::validate_phase(schema, &doc, &self.phase);
            for result in report.findings() {
                findings.push(to_finding(result));
            }
            // Only failed asserts (problems) gate ingestion; successful reports
            // are positive findings and never block.
            if report
                .failures()
                .iter()
                .any(|result| map_severity(result.severity) >= self.threshold)
            {
                failed = true;
            }
        }

        let outcome = if failed {
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
    use crate::service::validation::ValidatorConfig;

    /// A ruleset asserting the document has a `document` object at the root.
    const RULESET: &str = r#"{
        "title": "test",
        "patterns": [
            {
                "name": "required",
                "title": "required",
                "rules": [
                    {
                        "context": "$",
                        "checks": [
                            {
                                "kind": "assert",
                                "test": { "type": "exists", "path": "$.document" },
                                "message": "must have a document object"
                            }
                        ]
                    }
                ]
            }
        ]
    }"#;

    fn config(formats: Vec<Format>, mode: ValidationMode) -> ValidatorConfig {
        ValidatorConfig {
            name: "test".into(),
            backend: Default::default(),
            formats,
            rules: Vec::new(),
            phase: None,
            mode,
            threshold: Severity::Error,
            on_error: OnError::Block,
        }
    }

    fn validator(mode: ValidationMode) -> ScheckValidator {
        let schema = serde_json::from_str(RULESET).expect("valid ruleset");
        ScheckValidator::new(&config(vec![Format::CSAF], mode), vec![schema])
    }

    #[tokio::test]
    async fn passing_document_yields_passed() {
        let validator = validator(ValidationMode::Verify);
        let input = ValidatorInput {
            bytes: br#"{"document":{}}"#,
            format: Format::CSAF,
        };
        let report = validator.validate(&input).await.expect("validates");
        assert_eq!(report.outcome, ValidationOutcome::Passed);
    }

    #[tokio::test]
    async fn failing_document_yields_failed_with_findings() {
        let validator = validator(ValidationMode::Verify);
        let input = ValidatorInput {
            bytes: br#"{"other":true}"#,
            format: Format::CSAF,
        };
        let report = validator.validate(&input).await.expect("validates");
        assert_eq!(report.outcome, ValidationOutcome::Failed);
        assert!(!report.findings.is_empty());
    }

    #[tokio::test]
    async fn non_utf8_is_backend_error() {
        let validator = validator(ValidationMode::Report);
        let input = ValidatorInput {
            bytes: &[0xff, 0xfe, 0x00],
            format: Format::CSAF,
        };
        assert!(validator.validate(&input).await.is_err());
    }

    #[test]
    fn applies_to_matches_category_hint() {
        let schema = serde_json::from_str(RULESET).expect("valid ruleset");
        let validator = ScheckValidator::new(
            &config(vec![Format::SBOM], ValidationMode::Report),
            vec![schema],
        );
        assert!(validator.applies_to(Format::SPDX));
        assert!(validator.applies_to(Format::CycloneDX));
        assert!(!validator.applies_to(Format::CSAF));
    }

    #[test]
    fn parse_ruleset_rejects_unknown_extension() {
        let err = parse_ruleset(Path::new("rules.txt"), "{}").unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }
}
