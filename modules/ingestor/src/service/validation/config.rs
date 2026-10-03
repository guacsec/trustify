//! Configuration for semantic validators and construction of the validator set.
//!
//! The default configuration is empty, which disables validation entirely and
//! preserves the pre-existing ingestion behaviour. See ADR 00020.

use crate::service::{
    Format,
    validation::{
        OnError, ScheckValidator, Severity, ValidationMode, Validator, conforma, csaf, scheck,
    },
};
use anyhow::Context;
use std::{collections::HashSet, fs, path::PathBuf, sync::Arc};

/// Configuration for the complete set of validators.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct ValidatorsConfig {
    /// The validators to run, in order.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
}

/// Which backend implements a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// The in-process `scheck` semantic validator.
    #[default]
    Scheck,
    /// The in-process CSAF specification validator (`csaf-rs`).
    Csaf,
    /// A remote Conforma `ec validate input --server` instance.
    Conforma,
}

/// Configuration for a single validator.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ValidatorConfig {
    /// Stable identifier used in reports and logs.
    pub name: String,
    /// The backend implementing this validator.
    #[serde(default)]
    pub backend: Backend,
    /// Formats this validator applies to. A category (e.g. `sbom`) matches all
    /// of its concrete formats.
    #[serde(default)]
    pub formats: Vec<Format>,
    /// Ruleset files to load (scheck JSON `.json` or DSL `.scheck`).
    #[serde(default)]
    pub rules: Vec<PathBuf>,
    /// Optional backend-specific phase to activate (scheck backend).
    #[serde(default)]
    pub phase: Option<String>,
    /// CSAF validation profile / preset (csaf backend).
    ///
    /// For CSAF 2.0: `basic`, `extended`, `full`.
    /// For CSAF 2.1: additionally `mandatory`, `recommended`, `informative`,
    /// `schema`, `external-request-free`, `consistent-revision-history`,
    /// `consistent-date-times`, `ssvc`.
    ///
    /// Defaults to `basic` when omitted.
    #[serde(default)]
    pub profile: Option<String>,
    /// Remote Conforma server settings (required for the Conforma backend).
    #[serde(default)]
    pub conforma: Option<ConformaConfig>,
    /// Whether this validator runs automatically during ingestion.
    #[serde(default = "default_run_on_ingest")]
    pub run_on_ingest: bool,
    /// Whether findings only report, or gate ingestion.
    #[serde(default)]
    pub mode: ValidationMode,
    /// For verify mode, the lowest severity that blocks ingestion.
    #[serde(default = "default_threshold")]
    pub threshold: Severity,
    /// For verify mode, the behaviour when the validator itself errors.
    #[serde(default)]
    pub on_error: OnError,
}

fn default_threshold() -> Severity {
    Severity::Error
}

fn default_run_on_ingest() -> bool {
    true
}

/// URL and request timeout for a long-lived `ec validate input --server` instance.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ConformaConfig {
    /// Base URL of the Conforma server; `/v1/validate/input` is appended.
    pub url: String,
    /// Maximum duration of one request, including response-body reading.
    #[serde(default = "default_conforma_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_conforma_timeout_seconds() -> u64 {
    120
}

/// Build the validator set from configuration.
///
/// Returns an empty set when no validators are configured, preserving the
/// default validation-disabled behaviour.
pub fn build(config: &ValidatorsConfig) -> Result<Vec<Arc<dyn Validator>>, anyhow::Error> {
    let mut validators: Vec<Arc<dyn Validator>> = Vec::with_capacity(config.validators.len());
    let mut names = HashSet::with_capacity(config.validators.len());
    for validator in &config.validators {
        anyhow::ensure!(
            names.insert(&validator.name),
            "duplicate validator name: {}",
            validator.name
        );
        match validator.backend {
            Backend::Scheck => validators.push(Arc::new(build_scheck(validator)?)),
            Backend::Csaf => validators.push(Arc::new(csaf::Validator::new(validator))),
            Backend::Conforma => validators.push(Arc::new(conforma::build(validator)?)),
        }
    }
    Ok(validators)
}

fn build_scheck(config: &ValidatorConfig) -> Result<ScheckValidator, anyhow::Error> {
    let mut schemas = Vec::with_capacity(config.rules.len());
    for path in &config.rules {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("reading scheck ruleset {}", path.display()))?;
        schemas.push(scheck::parse_ruleset(path, &contents)?);
    }
    Ok(ScheckValidator::new(config, schemas))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_builds_empty_set() {
        let config = ValidatorsConfig::default();
        let validators = build(&config).expect("builds");
        assert!(validators.is_empty());
    }

    #[test]
    fn yaml_round_trips_with_defaults() {
        let yaml = r#"
validators:
  - name: scheck-csaf
    formats: [csaf]
    rules: []
"#;
        let config: ValidatorsConfig = serde_yml::from_str(yaml).expect("parses");
        assert_eq!(config.validators.len(), 1);
        let validator = &config.validators[0];
        assert_eq!(validator.backend, Backend::Scheck);
        assert_eq!(validator.mode, ValidationMode::Report);
        assert_eq!(validator.threshold, Severity::Error);
        assert_eq!(validator.on_error, OnError::Block);
        assert!(validator.run_on_ingest);
        assert!(validator.conforma.is_none());
    }

    #[test]
    fn yaml_round_trips_csaf_backend() {
        let yaml = r#"
validators:
  - name: csaf-spec
    backend: csaf
    formats: [csaf]
    profile: extended
"#;
        let config: ValidatorsConfig = serde_yml::from_str(yaml).expect("parses");
        assert_eq!(config.validators.len(), 1);
        let validator = &config.validators[0];
        assert_eq!(validator.backend, Backend::Csaf);
        assert_eq!(validator.profile.as_deref(), Some("extended"));
        assert_eq!(validator.mode, ValidationMode::Report);
        assert_eq!(validator.threshold, Severity::Error);
        assert_eq!(validator.on_error, OnError::Block);
        assert!(validator.run_on_ingest);
    }

    #[test]
    fn yaml_configures_remote_conforma_server() {
        let config: ValidatorsConfig = serde_yml::from_str(
            "validators:\n  - name: policy-a\n    backend: conforma\n    formats: [spdx]\n    run_on_ingest: false\n    conforma:\n      url: https://ec.example.test\n",
        )
        .expect("parses");
        let validator = &config.validators[0];
        assert_eq!(validator.backend, Backend::Conforma);
        assert!(!validator.run_on_ingest);
        let conforma = validator.conforma.as_ref().expect("Conforma settings");
        assert_eq!(conforma.url, "https://ec.example.test");
        assert_eq!(conforma.timeout_seconds, 120);
    }

    #[test]
    fn builds_csaf_validator_from_config() {
        let config = ValidatorsConfig {
            validators: vec![ValidatorConfig {
                name: "csaf-spec".into(),
                backend: Backend::Csaf,
                formats: vec![Format::CSAF],
                rules: vec![],
                phase: None,
                profile: Some("basic".into()),
                conforma: None,
                run_on_ingest: true,
                mode: ValidationMode::Verify,
                threshold: Severity::Error,
                on_error: OnError::Block,
            }],
        };
        let validators = build(&config).expect("builds");
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].name(), "csaf-spec");
    }

    #[test]
    fn builds_scheck_validator_from_ruleset_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rules.json");
        std::fs::write(
            &path,
            r#"{"title":"t","patterns":[{"name":"p","title":"p","rules":[{"context":"$","checks":[{"kind":"assert","test":{"type":"exists","path":"$.x"},"message":"needs x"}]}]}]}"#,
        )
        .expect("write ruleset");

        let config = ValidatorsConfig {
            validators: vec![ValidatorConfig {
                name: "scheck".into(),
                backend: Backend::Scheck,
                formats: vec![Format::CSAF],
                rules: vec![path],
                phase: None,
                profile: None,
                conforma: None,
                run_on_ingest: true,
                mode: ValidationMode::Report,
                threshold: Severity::Error,
                on_error: OnError::Block,
            }],
        };

        let validators = build(&config).expect("builds");
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].name(), "scheck");
    }

    #[test]
    fn rejects_duplicate_validator_names() {
        let config: ValidatorsConfig =
            serde_yml::from_str("validators:\n  - name: duplicate\n  - name: duplicate\n")
                .expect("parses");
        assert!(
            build(&config)
                .unwrap_err()
                .to_string()
                .contains("duplicate validator name")
        );
    }
}
