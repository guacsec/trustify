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

/// Which backend implements a validator and its backend-specific settings.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Backend {
    /// The in-process `scheck` semantic validator.
    Scheck {
        /// Ruleset files to load (scheck JSON `.json` or DSL `.scheck`).
        #[serde(default)]
        rules: Vec<PathBuf>,
        /// Optional scheck phase to activate.
        #[serde(default)]
        phase: Option<String>,
    },
    /// The in-process CSAF specification validator (`csaf-rs`).
    Csaf {
        /// Validation profile / preset; defaults to `basic`.
        #[serde(default)]
        profile: Option<String>,
    },
    /// A remote Conforma `ec validate input --server` instance.
    Conforma(ConformaConfig),
}

impl Default for Backend {
    fn default() -> Self {
        Self::Scheck {
            rules: Vec::new(),
            phase: None,
        }
    }
}

/// Configuration for a single validator.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ValidatorConfig {
    /// Stable identifier used in reports and logs.
    pub name: String,
    /// Backend and its backend-specific settings.
    #[serde(default)]
    pub backend: Backend,
    /// Formats this validator applies to. A category (e.g. `sbom`) matches all
    /// of its concrete formats.
    #[serde(default)]
    pub formats: Vec<Format>,
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
        match &validator.backend {
            Backend::Scheck { rules, phase } => {
                validators.push(Arc::new(build_scheck(validator, rules, phase.as_deref())?));
            }
            Backend::Csaf { profile } => {
                validators.push(Arc::new(csaf::Validator::new(
                    validator,
                    profile.as_deref(),
                )));
            }
            Backend::Conforma(conforma) => {
                validators.push(Arc::new(conforma::build(validator, conforma)?));
            }
        }
    }
    Ok(validators)
}

fn build_scheck(
    config: &ValidatorConfig,
    rules: &[PathBuf],
    phase: Option<&str>,
) -> Result<ScheckValidator, anyhow::Error> {
    let mut schemas = Vec::with_capacity(rules.len());
    for path in rules {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("reading scheck ruleset {}", path.display()))?;
        schemas.push(scheck::parse_ruleset(path, &contents)?);
    }
    Ok(ScheckValidator::new(config, schemas, phase))
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
    fn example_config_parses() {
        let config: ValidatorsConfig = serde_yml::from_str(include_str!(
            "../../../../../etc/validators/validators.yaml"
        ))
        .expect("parses example config");
        assert_eq!(config.validators.len(), 4);
    }

    #[test]
    fn yaml_round_trips_with_defaults() {
        let yaml = r#"
validators:
  - name: scheck-defaults
    formats: [csaf]
  - name: scheck-configured
    backend:
      type: scheck
      rules: []
      phase: structural
    formats: [csaf]
"#;
        let config: ValidatorsConfig = serde_yml::from_str(yaml).expect("parses");
        assert_eq!(config.validators.len(), 2);
        let validator = &config.validators[0];
        assert!(matches!(
            &validator.backend,
            Backend::Scheck { rules, phase: None } if rules.is_empty()
        ));
        assert_eq!(validator.mode, ValidationMode::Report);
        assert_eq!(validator.threshold, Severity::Error);
        assert_eq!(validator.on_error, OnError::Block);
        assert!(validator.run_on_ingest);

        let validator = &config.validators[1];
        assert!(matches!(
            &validator.backend,
            Backend::Scheck { rules, phase: Some(phase) }
                if rules.is_empty() && phase == "structural"
        ));
    }

    #[test]
    fn yaml_round_trips_csaf_backend() {
        let yaml = r#"
validators:
  - name: csaf-spec
    backend:
      type: csaf
      profile: extended
    formats: [csaf]
"#;
        let config: ValidatorsConfig = serde_yml::from_str(yaml).expect("parses");
        assert_eq!(config.validators.len(), 1);
        let validator = &config.validators[0];
        assert!(matches!(
            &validator.backend,
            Backend::Csaf { profile: Some(profile) } if profile == "extended"
        ));
        assert_eq!(validator.mode, ValidationMode::Report);
        assert_eq!(validator.threshold, Severity::Error);
        assert_eq!(validator.on_error, OnError::Block);
        assert!(validator.run_on_ingest);
    }

    #[test]
    fn json_configures_remote_conforma_server() {
        let config: ValidatorsConfig = serde_json::from_value(serde_json::json!({
            "validators": [{
                "name": "policy-a",
                "backend": { "type": "conforma", "url": "https://ec.example.test" },
                "formats": ["spdx"],
                "run_on_ingest": false
            }]
        }))
        .expect("parses");
        let validator = &config.validators[0];
        let Backend::Conforma(conforma) = &validator.backend else {
            panic!("expected Conforma backend")
        };
        assert!(!validator.run_on_ingest);
        assert_eq!(conforma.url, "https://ec.example.test");
        assert_eq!(conforma.timeout_seconds, 120);
    }

    #[test]
    fn conforma_backend_requires_settings() {
        assert!(
            serde_json::from_value::<ValidatorsConfig>(serde_json::json!({
                "validators": [{ "name": "policy-a", "backend": { "type": "conforma" } }]
            }))
            .is_err()
        );
    }

    #[test]
    fn rejects_settings_for_another_backend() {
        assert!(
            serde_json::from_value::<ValidatorsConfig>(serde_json::json!({
                "validators": [{
                    "name": "csaf",
                    "backend": { "type": "csaf", "url": "https://ec.example.test" }
                }]
            }))
            .is_err()
        );
    }

    #[test]
    fn builds_csaf_validator_from_config() {
        let config = ValidatorsConfig {
            validators: vec![ValidatorConfig {
                name: "csaf-spec".into(),
                backend: Backend::Csaf {
                    profile: Some("basic".into()),
                },
                formats: vec![Format::CSAF],
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
                backend: Backend::Scheck {
                    rules: vec![path],
                    phase: None,
                },
                formats: vec![Format::CSAF],
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
        let config: ValidatorsConfig = serde_json::from_value(serde_json::json!({
            "validators": [{ "name": "duplicate" }, { "name": "duplicate" }]
        }))
        .expect("parses");
        assert!(
            build(&config)
                .unwrap_err()
                .to_string()
                .contains("duplicate validator name")
        );
    }
}
