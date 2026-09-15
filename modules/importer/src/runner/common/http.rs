use crate::{
    model::auth::{AuthConfig, AuthMethod, CredentialConfig},
    runner::common::Error,
};
use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{
    Client,
    header::{self, HeaderName, HeaderValue},
};

/// Builds an authenticated (or unauthenticated) `reqwest::Client`.
///
/// When `auth` is `None` a plain client with no default headers is returned.
/// When `auth` is `Some`, credentials are resolved from their [`AuthConfig`]
/// and set as default headers so every request the client makes carries them.
pub fn build_http_client(
    auth: Option<&AuthConfig>,
    credential_config: &CredentialConfig,
) -> Result<Client, Error> {
    let Some(auth) = auth else {
        return Ok(Client::default());
    };

    let mut headers = header::HeaderMap::new();

    match &auth.method {
        AuthMethod::Bearer { token } => {
            let resolved = token
                .resolve(credential_config)
                .map_err(|e| Error::Processing(anyhow!("bearer token resolution failed: {e}")))?;
            let value = format!("Bearer {resolved}");
            let mut header_val = HeaderValue::from_str(&value)?;
            header_val.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, header_val);
        }
        AuthMethod::Basic { username, password } => {
            let user = username.resolve(credential_config).map_err(|e| {
                Error::Processing(anyhow!("basic auth username resolution failed: {e}"))
            })?;
            let pass = password.resolve(credential_config).map_err(|e| {
                Error::Processing(anyhow!("basic auth password resolution failed: {e}"))
            })?;
            let encoded = BASE64_STANDARD.encode(format!("{user}:{pass}"));
            let value = format!("Basic {encoded}");
            let mut header_val = HeaderValue::from_str(&value)?;
            header_val.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, header_val);
        }
        AuthMethod::ApiKey { header, value } => {
            let resolved = value
                .resolve(credential_config)
                .map_err(|e| Error::Processing(anyhow!("api key resolution failed: {e}")))?;
            let header_name = HeaderName::from_bytes(header.as_bytes())
                .map_err(|e| Error::Processing(anyhow!("invalid api key header name: {e}")))?;
            let mut header_val = HeaderValue::from_str(&resolved)?;
            header_val.set_sensitive(true);
            headers.insert(header_name, header_val);
        }
    }

    Ok(Client::builder().default_headers(headers).build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::auth::{AuthConfig, AuthMethod, CredentialSource};

    /// Verifies that `build_http_client(None)` returns a client without error.
    #[test]
    fn build_http_client_none_succeeds() {
        let client = build_http_client(None, &CredentialConfig::default());
        assert!(client.is_ok());
    }

    /// Verifies that `build_http_client` succeeds with a Bearer auth config.
    #[test]
    fn build_http_client_bearer_inline_succeeds() {
        // Given a Bearer auth config with an inline token
        let auth = AuthConfig {
            method: AuthMethod::Bearer {
                token: CredentialSource::Inline("test-token".into()),
            },
        };

        // When building the client
        let result = build_http_client(Some(&auth), &CredentialConfig::default());

        // Then no error is returned
        assert!(result.is_ok());
    }

    /// Verifies that `build_http_client` fails when the env var does not match the required prefix.
    #[test]
    fn build_http_client_bearer_env_rejects_disallowed_prefix() {
        // Given a Bearer auth config referencing an env var without the required prefix
        let auth = AuthConfig {
            method: AuthMethod::Bearer {
                token: CredentialSource::Env("TRUSTD_DB_PASSWORD".into()),
            },
        };
        let credential_config = CredentialConfig {
            allowed_prefixes: Some(vec!["IMPORTER_AUTH_".into()]),
            allowed_paths: None,
        };

        // When building the client
        let result = build_http_client(Some(&auth), &credential_config);

        // Then an error is returned
        assert!(result.is_err());
    }

    /// Verifies that `build_http_client` succeeds when the env var matches the required prefix.
    #[test]
    fn build_http_client_bearer_env_allowed_prefix_succeeds() {
        // Given the env var is set with the correct prefix
        // SAFETY: test-only mutation, single-threaded test binary
        unsafe { std::env::set_var("IMPORTER_AUTH_HTTP_TEST_TOKEN", "test-value") };

        let auth = AuthConfig {
            method: AuthMethod::Bearer {
                token: CredentialSource::Env("IMPORTER_AUTH_HTTP_TEST_TOKEN".into()),
            },
        };
        let credential_config = CredentialConfig {
            allowed_prefixes: Some(vec!["IMPORTER_AUTH_".into()]),
            allowed_paths: None,
        };

        // When building the client
        let result = build_http_client(Some(&auth), &credential_config);

        // SAFETY: test-only mutation, single-threaded test binary
        unsafe { std::env::remove_var("IMPORTER_AUTH_HTTP_TEST_TOKEN") };

        // Then no error is returned
        assert!(result.is_ok());
    }
}
