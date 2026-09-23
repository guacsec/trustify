use std::{env::VarError, fs::read_to_string, io::Error};
use trustify_common::env::EnvSource;
use utoipa::ToSchema;

/// How a credential value is sourced at import time.
///
/// Inline stores the value directly (dev only). Env and File store
/// only a reference — the value is resolved from the environment or
/// filesystem at each import run, enabling K8s Secret rotation.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum CredentialSource {
    /// Literal value stored in the database.
    ///
    /// **Security:** the credential is stored in plaintext in the database.
    /// Prefer [`CredentialSource::Env`] or [`CredentialSource::File`] for production use.
    Inline(String),
    /// Name of an environment variable read at import time.
    Env(String),
    /// Filesystem path to a file whose content is read at import time.
    File(String),
}

/// Errors that can occur when resolving a [`CredentialSource`] to its value.
#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("failed to read environment variable '{name}': {error}")]
    EnvVar {
        name: String,
        #[source]
        error: VarError,
    },
    #[error(
        "env var credential source is disabled; set IMPORTER_ENV_PREFIXES to allow one or more prefixes"
    )]
    EnvVarDisabled,
    #[error(
        "env var '{name}' is not allowed; must start with one of the following prefixes: {allowed_prefixes:?}"
    )]
    EnvVarNotAllowed {
        name: String,
        allowed_prefixes: Vec<String>,
    },
    #[error("failed to read file '{path}': {error}")]
    FileRead {
        path: String,
        #[source]
        error: Error,
    },
    #[error(
        "file credential source is disabled; set IMPORTER_CREDENTIAL_PATHS to allow one or more paths"
    )]
    FileDisabled,
    #[error(
        "file '{path}' is not allowed; must be in one of the following paths: {allowed_paths:?}"
    )]
    FileNotAllowed {
        path: String,
        allowed_paths: Vec<String>,
    },
}

impl CredentialSource {
    /// Resolves the credential to its string value.
    ///
    /// `env_lookup` is called to read environment variables. Production callers
    /// pass `()`; tests pass a `&[("KEY", "val")]` slice to avoid mutating
    /// the process environment.
    pub fn resolve(
        &self,
        credential_config: &CredentialConfig,
        env_lookup: impl EnvSource,
    ) -> Result<String, AuthError> {
        match self {
            Self::Inline(v) => Ok(v.clone()),
            Self::Env(name) => {
                let prefixes = &credential_config.allowed_prefixes;
                if prefixes.is_empty() {
                    return Err(AuthError::EnvVarDisabled);
                }
                if !prefixes.iter().any(|p| name.starts_with(p)) {
                    return Err(AuthError::EnvVarNotAllowed {
                        name: name.clone(),
                        allowed_prefixes: prefixes.to_vec(),
                    });
                }
                env_lookup.lookup(name).map_err(|e| AuthError::EnvVar {
                    name: name.clone(),
                    error: e,
                })
            }
            Self::File(path) => {
                let paths = &credential_config.allowed_paths;
                if paths.is_empty() {
                    return Err(AuthError::FileDisabled);
                }
                // Require the path to equal an allowed entry exactly, or be
                // a proper sub-path of one (i.e. the prefix ends at a '/').
                // A bare `starts_with` check would allow "/run/secrets.evil"
                // to bypass an allowlist entry of "/run/secrets".
                if !paths
                    .iter()
                    .any(|p| path == p.as_str() || path.starts_with(&format!("{}/", p)))
                {
                    return Err(AuthError::FileNotAllowed {
                        path: path.clone(),
                        allowed_paths: paths.to_vec(),
                    });
                }
                read_to_string(path).map_err(|e| AuthError::FileRead {
                    path: path.clone(),
                    error: e,
                })
            }
        }
    }
}

/// HTTP authentication method applied on each import request.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AuthMethod {
    /// HTTP Basic authentication.
    Basic {
        username: CredentialSource,
        password: CredentialSource,
    },
    /// Bearer token in the Authorization header.
    Bearer { token: CredentialSource },
    /// Arbitrary header/value pair (e.g. API key headers).
    ApiKey {
        header: String,
        value: CredentialSource,
    },
}

/// Authentication configuration for HTTP-based importers.
///
/// Wraps an [`AuthMethod`] whose credentials are resolved from
/// a [`CredentialSource`] at import time — not at configuration time.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
pub struct AuthConfig {
    pub method: AuthMethod,
}

/// Operator-level restrictions on credential resolution.
///
/// Set at application startup via CLI flags or environment variables.
/// These constraints cannot be changed at runtime by users who have
/// importer write permission, providing a security boundary above
/// per-importer [`AuthConfig`].
#[derive(Debug, Clone, Default)]
pub struct CredentialConfig {
    /// Required prefixes for env var names. Empty vec = allow none.
    pub allowed_prefixes: Vec<String>,
    /// Allowed base paths for file credentials. Empty vec = allow none.
    pub allowed_paths: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::fs::write;

    use tempfile::tempdir;

    use super::*;

    /// Verifies that an Inline credential resolves to its literal value.
    #[test]
    fn credential_source_inline_resolves_to_value() {
        let src = CredentialSource::Inline("my-secret".into());
        assert_eq!(
            src.resolve(&CredentialConfig::default(), ()).unwrap(),
            "my-secret"
        );
    }

    /// Verifies that an Env credential reads the named environment variable.
    #[test]
    fn credential_source_env_reads_variable() {
        let credential_config = CredentialConfig {
            allowed_prefixes: vec!["IMPORTER_AUTH_".into()],
            allowed_paths: vec![],
        };
        let src = CredentialSource::Env("IMPORTER_AUTH_TC6090_TEST_VAR".into());
        assert_eq!(
            src.resolve(
                &credential_config,
                &[("IMPORTER_AUTH_TC6090_TEST_VAR", "env-value")],
            )
            .unwrap(),
            "env-value"
        );
    }

    /// Verifies that an Env credential errors when the variable is not set.
    #[test]
    fn credential_source_env_errors_when_not_set() {
        let credential_config = CredentialConfig {
            allowed_prefixes: vec!["IMPORTER_AUTH_".into()],
            allowed_paths: vec![],
        };
        let src = CredentialSource::Env("IMPORTER_AUTH_TC6090_MISSING_VAR".into());
        assert!(matches!(
            src.resolve(&credential_config, ()),
            Err(AuthError::EnvVar { name, .. }) if name == "IMPORTER_AUTH_TC6090_MISSING_VAR"
        ));
    }

    /// Verifies that an Env credential errors when the variable name does not match the allowed prefix.
    #[test]
    fn credential_source_env_errors_when_not_allowed() {
        let src = CredentialSource::Env("NOT_ALLOWED_VAR".into());
        let credential_config = CredentialConfig {
            allowed_prefixes: vec!["ALLOWED_".into()],
            allowed_paths: vec![],
        };
        assert!(matches!(
            src.resolve(&credential_config, ()),
            Err(AuthError::EnvVarNotAllowed { name, allowed_prefixes })
                if name == "NOT_ALLOWED_VAR"
                    && allowed_prefixes == credential_config.allowed_prefixes
        ));
    }

    /// Verifies that an Env credential is valid when the variable matches the allowed prefix.
    #[test]
    fn credential_source_env_is_valid_when_allowed() {
        let credential_config = CredentialConfig {
            allowed_prefixes: vec!["ALLOWED_".into()],
            allowed_paths: vec![],
        };
        let src = CredentialSource::Env("ALLOWED_VAR".into());
        assert!(matches!(
            src.resolve(&credential_config, &[("ALLOWED_VAR", "allowed-value")]),
            Ok(value) if value == "allowed-value"
        ));
    }

    /// Verifies that a File credential reads file content.
    #[test]
    fn credential_source_file_reads_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        write(&path, "file-secret").unwrap();
        let src = CredentialSource::File(path.to_string_lossy().into_owned());
        let credential_config = CredentialConfig {
            allowed_prefixes: vec![],
            allowed_paths: vec![dir.path().to_string_lossy().into_owned()],
        };
        assert_eq!(src.resolve(&credential_config, ()).unwrap(), "file-secret");
    }

    /// Verifies that a File credential is valid when the file is under an allowed path.
    #[test]
    fn credential_source_file_is_valid_when_allowed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        write(&path, "file-secret").unwrap();
        let src = CredentialSource::File(path.to_string_lossy().into_owned());
        let credential_config = CredentialConfig {
            allowed_prefixes: vec![],
            allowed_paths: vec![dir.path().to_string_lossy().into_owned()],
        };
        assert!(matches!(
            src.resolve(&credential_config, ()),
            Ok(value) if value == "file-secret"
        ));
    }

    /// Verifies that a File credential errors when the file does not exist.
    #[test]
    fn credential_source_file_errors_when_missing() {
        let credential_config = CredentialConfig {
            allowed_prefixes: vec![],
            allowed_paths: vec!["/nonexistent/path".to_string()],
        };
        let src = CredentialSource::File("/nonexistent/path/secret.txt".to_string());
        assert!(src.resolve(&credential_config, ()).is_err());
    }

    /// Verifies that an Env credential errors when env var source is disabled (empty prefixes).
    #[test]
    fn credential_source_env_errors_when_disabled() {
        let src = CredentialSource::Env("IMPORTER_AUTH_VAR".into());
        assert!(matches!(
            src.resolve(&CredentialConfig::default(), ()),
            Err(AuthError::EnvVarDisabled)
        ));
    }

    /// Verifies that an Env credential errors when allowed_prefixes is explicitly empty.
    #[test]
    fn credential_source_env_errors_when_prefixes_empty() {
        let src = CredentialSource::Env("IMPORTER_AUTH_VAR".into());
        let credential_config = CredentialConfig {
            allowed_prefixes: vec![],
            allowed_paths: vec![],
        };
        assert!(matches!(
            src.resolve(&credential_config, ()),
            Err(AuthError::EnvVarDisabled)
        ));
    }

    /// Verifies that a File credential errors when file source is disabled (empty paths).
    #[test]
    fn credential_source_file_errors_when_disabled() {
        let src = CredentialSource::File("/var/run/secrets/token".into());
        assert!(matches!(
            src.resolve(&CredentialConfig::default(), ()),
            Err(AuthError::FileDisabled)
        ));
    }

    /// Verifies that a File credential errors when allowed_paths is explicitly empty.
    #[test]
    fn credential_source_file_errors_when_paths_empty() {
        let src = CredentialSource::File("/var/run/secrets/token".into());
        let credential_config = CredentialConfig {
            allowed_prefixes: vec![],
            allowed_paths: vec![],
        };
        assert!(matches!(
            src.resolve(&credential_config, ()),
            Err(AuthError::FileDisabled)
        ));
    }

    /// Verifies that a File credential errors when the file path is outside allowed directories.
    #[test]
    fn credential_source_file_errors_when_not_allowed() {
        let src = CredentialSource::File("/not-allowed/path/secret.txt".to_string());
        let credential_config = CredentialConfig {
            allowed_prefixes: vec![],
            allowed_paths: vec!["/allowed/path".to_string()],
        };
        assert!(matches!(
            src.resolve(&credential_config, ()),
            Err(AuthError::FileNotAllowed { path, allowed_paths })
                if path == "/not-allowed/path/secret.txt"
                    && allowed_paths == credential_config.allowed_paths
        ));
    }
}
