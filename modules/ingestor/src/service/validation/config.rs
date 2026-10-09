//! Configuration for semantic validators and construction of the validator set.
//!
//! The default configuration is empty, which disables validation entirely and
//! preserves the pre-existing ingestion behaviour. See ADR 00021.

#[cfg(feature = "semantic-validation")]
use crate::service::validation::{ScheckValidator, conforma, csaf, scheck};
use crate::service::{
    Format,
    validation::{OnError, Severity, ValidationMode, Validator, store::Caps},
};
#[cfg(feature = "semantic-validation")]
use anyhow::Context;
use std::{collections::HashSet, path::PathBuf, sync::Arc};

/// Configuration for the complete set of validators.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ValidatorsConfig {
    /// The validators to run, in order.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Whether results are stored. When false, every validator falls back to
    /// logging its result at `debug` regardless of its own `persist` setting.
    #[serde(default = "default_persist")]
    pub persist_reports: bool,
    /// Bounds on how much of each report is stored.
    #[serde(default)]
    pub caps: Caps,
}

impl Default for ValidatorsConfig {
    fn default() -> Self {
        Self {
            validators: Vec::new(),
            persist_reports: default_persist(),
            caps: Caps::default(),
        }
    }
}

/// When a validator re-runs against a document it has already seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Revalidate {
    /// Always run the validator, even for an unchanged document.
    #[default]
    Always,
    /// Skip the run when the document and the validator configuration are
    /// unchanged since the stored result.
    ///
    /// Only safe for backends whose verdict depends entirely on inputs we can
    /// fingerprint. A remote backend's policy can change without any change
    /// here, so this would serve a stale verdict.
    OnChange,
}

/// What a validator contributes to the stored report, and when.
///
/// Derived from configuration once, at build time, so the ingest path does not
/// have to consult the configuration again.
#[derive(Clone, Debug)]
pub struct Persistence {
    /// Whether results from this validator are stored.
    pub persist: bool,
    /// Whether an unchanged document is validated again.
    pub revalidate: Revalidate,
    /// Bounds on how much of the report is stored.
    pub caps: Caps,
    /// Digest of the configuration that produces this validator's verdicts.
    pub fingerprint: String,
}

impl Default for Persistence {
    /// Store with the default caps, under an unknown configuration.
    fn default() -> Self {
        Self {
            persist: default_persist(),
            revalidate: Revalidate::default(),
            caps: Caps::default(),
            fingerprint: String::new(),
        }
    }
}

impl Persistence {
    /// Derive the persistence settings for one validator.
    ///
    /// `backend_inputs` carries the bytes that identify the backend's own
    /// inputs — ruleset contents for scheck, for instance — which the
    /// serialized configuration does not capture. Changing any of them yields
    /// a new fingerprint, so the next run records a new row rather than
    /// claiming the old verdict came from the new configuration.
    pub fn new(
        global: &ValidatorsConfig,
        config: &ValidatorConfig,
        backend_inputs: &[&[u8]],
    ) -> Result<Self, anyhow::Error> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        // Only what can change a verdict: the persistence settings themselves
        // are deliberately excluded, so toggling them does not look like a new
        // result.
        for part in [
            config.name.as_bytes(),
            serde_json::to_string(&config.backend)?.as_bytes(),
            serde_json::to_string(&config.formats)?.as_bytes(),
            serde_json::to_string(&config.mode)?.as_bytes(),
            serde_json::to_string(&config.threshold)?.as_bytes(),
            serde_json::to_string(&config.on_error)?.as_bytes(),
        ] {
            hasher.update(part);
            hasher.update(b"\0");
        }
        for input in backend_inputs {
            hasher.update(input);
            hasher.update(b"\0");
        }

        Ok(Self {
            persist: global.persist_reports && config.persist,
            revalidate: config.revalidate,
            caps: global.caps,
            fingerprint: hex::encode(hasher.finalize()),
        })
    }
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
    /// Whether results from this validator are stored.
    #[serde(default = "default_persist")]
    pub persist: bool,
    /// Whether an unchanged document is validated again.
    #[serde(default)]
    pub revalidate: Revalidate,
}

fn default_threshold() -> Severity {
    Severity::Error
}

fn default_run_on_ingest() -> bool {
    true
}

fn default_persist() -> bool {
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
        validators.push(build_one(config, validator)?);
    }
    Ok(validators)
}

/// Build a single validator from its configuration.
// Without any backend compiled in, only the fallback arm below remains, which
// does not look at the global settings.
#[cfg_attr(not(feature = "semantic-validation"), allow(unused_variables))]
fn build_one(
    global: &ValidatorsConfig,
    validator: &ValidatorConfig,
) -> Result<Arc<dyn Validator>, anyhow::Error> {
    match &validator.backend {
        #[cfg(feature = "semantic-validation")]
        Backend::Scheck { rules, phase } => Ok(Arc::new(build_scheck(
            global,
            validator,
            rules,
            phase.as_deref(),
        )?)),
        #[cfg(feature = "semantic-validation")]
        Backend::Csaf { profile } => {
            // The profile selects which spec tests run, so it belongs to the
            // fingerprint; the serialized backend already carries it.
            let persistence = Persistence::new(global, validator, &[])?;
            Ok(Arc::new(csaf::Validator::new(
                validator,
                profile.as_deref(),
                persistence,
            )))
        }
        #[cfg(feature = "semantic-validation")]
        Backend::Conforma(conforma) => {
            // Nothing here fingerprints the remote policy -- it is configured
            // on the Conforma server and can change without us knowing, which
            // is why `Revalidate::OnChange` is unsafe for this backend.
            let persistence = Persistence::new(global, validator, &[])?;
            Ok(Arc::new(conforma::build(validator, conforma, persistence)?))
        }
        #[allow(unreachable_patterns)]
        backend => anyhow::bail!(
            "validator '{}' uses backend {backend:?}, which is not compiled into this build \
             (the 'semantic-validation' feature is disabled)",
            validator.name,
        ),
    }
}

#[cfg(feature = "semantic-validation")]
fn build_scheck(
    global: &ValidatorsConfig,
    config: &ValidatorConfig,
    rules: &[PathBuf],
    phase: Option<&str>,
) -> Result<ScheckValidator, anyhow::Error> {
    let mut schemas = Vec::with_capacity(rules.len());
    let mut sources = Vec::with_capacity(rules.len());
    for path in rules {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading scheck ruleset {}", path.display()))?;
        schemas.push(scheck::parse_ruleset(path, &contents)?);
        sources.push(contents);
    }

    // The configuration records ruleset paths, not their contents: editing a
    // ruleset in place has to change the fingerprint.
    let inputs = sources.iter().map(|s| s.as_bytes()).collect::<Vec<_>>();
    let persistence = Persistence::new(global, config, &inputs)?;

    Ok(ScheckValidator::new(config, schemas, phase, persistence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_defaults_to_storing_everything() {
        let config = ValidatorsConfig::default();
        assert!(config.persist_reports);

        let config: ValidatorsConfig =
            serde_yml::from_str("validators:\n  - name: v\n").expect("parses");
        let validator = &config.validators[0];
        assert!(validator.persist);
        // Never skip a run by default -- a cached verdict is only safe when we
        // can prove the inputs are unchanged.
        assert_eq!(validator.revalidate, Revalidate::Always);
    }

    #[test]
    fn global_persist_reports_overrides_validators() {
        let config: ValidatorsConfig = serde_yml::from_str(
            "persist_reports: false\nvalidators:\n  - name: v\n    persist: true\n",
        )
        .expect("parses");

        let validators = build(&config).expect("builds");
        assert!(!validators[0].persistence().persist);
    }

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

    #[cfg(feature = "semantic-validation")]
    #[test]
    fn builds_csaf_validator_from_config() {
        let config = ValidatorsConfig {
            persist_reports: true,
            caps: Default::default(),
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
                persist: true,
                revalidate: Revalidate::Always,
            }],
        };
        let validators = build(&config).expect("builds");
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].name(), "csaf-spec");
    }

    #[cfg(feature = "semantic-validation")]
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
            persist_reports: true,
            caps: Default::default(),
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
                persist: true,
                revalidate: Revalidate::Always,
            }],
        };

        let validators = build(&config).expect("builds");
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].name(), "scheck");

        // Editing the ruleset in place has to change the fingerprint: the
        // configuration only records the path.
        let before = validators[0].persistence().fingerprint.clone();
        std::fs::write(
            dir.path().join("rules.json"),
            r#"{"title":"t","patterns":[{"name":"p","title":"p","rules":[{"context":"$","checks":[{"kind":"assert","test":{"type":"exists","path":"$.y"},"message":"needs y"}]}]}]}"#,
        )
        .expect("rewrite ruleset");
        let validators = build(&config).expect("builds");
        assert_ne!(validators[0].persistence().fingerprint, before);
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
