//! Configuration for semantic validators and construction of the validator set.
//!
//! The default configuration is empty, which disables validation entirely and
//! preserves the pre-existing ingestion behaviour. See ADR 00020.

use crate::service::{
    Format,
    validation::{OnError, ScheckValidator, Severity, ValidationMode, Validator, scheck},
};
use anyhow::Context;
use std::{fs, path::PathBuf, sync::Arc};

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
    /// Optional backend-specific phase to activate.
    #[serde(default)]
    pub phase: Option<String>,
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

/// Build the validator set from configuration.
///
/// Returns an empty set when no validators are configured, preserving the
/// default validation-disabled behaviour.
pub fn build(config: &ValidatorsConfig) -> Result<Vec<Arc<dyn Validator>>, anyhow::Error> {
    let mut validators: Vec<Arc<dyn Validator>> = Vec::with_capacity(config.validators.len());
    for validator in &config.validators {
        match validator.backend {
            Backend::Scheck => validators.push(Arc::new(build_scheck(validator)?)),
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
                mode: ValidationMode::Report,
                threshold: Severity::Error,
                on_error: OnError::Block,
            }],
        };

        let validators = build(&config).expect("builds");
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].name(), "scheck");
    }
}
