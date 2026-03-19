//! Server side authentication (verification)

mod claims;
mod default;
mod validate;

pub use default::*;

#[cfg(feature = "actix")]
pub mod actix;
pub mod config;
pub mod error;
pub mod user;

use crate::{
    authenticator::claims::ValidatedAccessToken, authenticator::config::AuthenticatorConfig,
};
use anyhow::anyhow;
use biscuit::jws::Compact;
use claims::AccessTokenClaims;
use config::AuthenticatorClientConfig;
use error::AuthenticationError;
use futures_util::{StreamExt, TryStreamExt, stream};
use jsonpath_rust::{
    parser::{model::JpQuery, parse_json_path},
    query::js_path_process,
};
use openid::{Client, Configurable, Discovered, Empty, Jws};
use serde_json::Value;
use std::{collections::HashMap, ops::Deref};
use tracing::instrument;
use trustify_common::reqwest::ClientFactory;

/// An authenticator to authenticate incoming requests.
#[derive(Clone)]
pub struct Authenticator {
    pub clients: Vec<AuthenticatorClient>,
}

impl Authenticator {
    fn from_clients(clients: Vec<AuthenticatorClient>) -> Self {
        Self { clients }
    }

    pub async fn from_config(config: Option<AuthenticatorConfig>) -> anyhow::Result<Option<Self>> {
        let config = match config {
            Some(config) => config,
            None => return Ok(None),
        };

        Ok(Some(Self::from_configs(config.clients).await?))
    }

    pub async fn from_configs<I>(configs: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = AuthenticatorClientConfig>,
    {
        let clients = stream::iter(configs)
            .map(Ok)
            .and_then(|config| async move { create_client(config).await })
            .try_collect()
            .await?;

        Ok(Self::from_clients(clients))
    }

    fn find_client(
        &self,
        token: &Compact<AccessTokenClaims, Empty>,
    ) -> Result<Option<&AuthenticatorClient>, AuthenticationError> {
        let unverified_payload = token.unverified_payload().map_err(|err| {
            log::info!("Failed to decode token payload: {err}");
            AuthenticationError::Failed
        })?;

        let Some(client_id) =
            &unverified_payload
                .azp
                .or_else(|| match &unverified_payload.extended_claims {
                    Value::Object(values) => values
                        .get("client_id")
                        .and_then(|value| value.as_str().map(ToString::to_string)),
                    _ => None,
                })
        else {
            // Right now, we do require the client id of the access token. For some, this comes in
            // form of the `azp` claim. For others, that might be different. Right now we know about
            // AWS using 'client_id'.
            log::warn!(
                "Token did neither contain an 'azp' nor a 'client_id' claim. We do require this."
            );
            return Err(AuthenticationError::Failed);
        };

        log::debug!(
            "Searching client for: {} / {}",
            unverified_payload.iss,
            client_id
        );

        // find the client to use

        let client = self.clients.iter().find(|client| {
            let provider_iss = &client.provider.config().issuer;
            let provider_client_id = &client.client_id;

            log::debug!("Checking client: {provider_iss} / {provider_client_id}");
            if provider_iss != &unverified_payload.iss {
                return false;
            }

            if client_id != provider_client_id {
                return false;
            }

            true
        });

        // return the result

        Ok(client)
    }

    /// Validate a bearer token.
    #[instrument(level = "debug", skip_all, fields(token = token.as_ref()), ret)]
    pub async fn validate_token<S: AsRef<str>>(
        &self,
        token: S,
    ) -> Result<ValidatedAccessToken, AuthenticationError> {
        let mut token: Compact<AccessTokenClaims, Empty> = Jws::new_encoded(token.as_ref());

        let client = self.find_client(&token)?.ok_or_else(|| {
            log::debug!("Unable to find client");
            AuthenticationError::Failed
        })?;

        log::debug!("Using client: {}", client.client_id);

        client.decode_token(&mut token).map_err(|err| {
            log::debug!("Failed to decode token: {err}");
            AuthenticationError::Failed
        })?;

        log::debug!("Token: {:?}", token);

        validate::validate_token(client, &token, client.audience.as_deref(), None).map_err(
            |err| {
                log::debug!("Validation failed: {err}");
                AuthenticationError::Failed
            },
        )?;

        match token {
            Compact::Decoded { payload, .. } => Ok(client.convert_token(payload)),
            Compact::Encoded(_) => Err(AuthenticationError::Failed),
        }
    }
}

async fn create_client(config: AuthenticatorClientConfig) -> anyhow::Result<AuthenticatorClient> {
    let mut client = ClientFactory::new();

    if config.tls_insecure {
        client = client.make_insecure();
    }

    for ca in config.tls_ca_certificates {
        client = client.add_ca_cert(ca);
    }

    let client = Client::<Discovered>::discover_with_client(
        client.build()?,
        config.client_id,
        None,
        None,
        config.issuer_url.parse()?,
    )
    .await?;

    log::debug!("Discovered OpenID: {:#?}", client.config());

    let group_selector = config
        .group_selector
        .map(|selector| {
            parse_json_path(&selector).map_err(|err| {
                anyhow!(
                    "Unable to parse JSON path group selector for client '{}' / '{}': {err}",
                    config.issuer_url,
                    client.client_id,
                )
            })
        })
        .transpose()?;

    let scope_selector = parse_json_path(&config.scope_selector).map_err(|err| {
        anyhow!(
            "Unable to parse JSON path scope selector for client '{}' / '{}': {err}",
            config.issuer_url,
            client.client_id,
        )
    })?;

    Ok(AuthenticatorClient {
        client,
        audience: config.required_audience,
        scope_mappings: config.scope_mappings,
        additional_permissions: config.additional_permissions,
        group_selector,
        group_mappings: config.group_mappings,
        scope_selector,
    })
}

#[derive(Clone)]
pub struct AuthenticatorClient {
    client: Client<Discovered>,
    audience: Option<String>,
    scope_mappings: HashMap<String, Vec<String>>,
    additional_permissions: Vec<String>,
    group_selector: Option<JpQuery>,
    group_mappings: HashMap<String, Vec<String>>,
    scope_selector: JpQuery,
}

impl AuthenticatorClient {
    /// Convert from a set of (verified!) access token claims into a [`ValidatedAccessToken`] struct.
    pub fn convert_token(&self, access_token: AccessTokenClaims) -> ValidatedAccessToken {
        let mut permissions = Self::map_items(
            Self::extract_scopes(&access_token.extended_claims, &self.scope_selector),
            &self.scope_mappings,
        );
        permissions.extend(self.additional_permissions.clone());
        let groups = self
            .group_selector
            .as_ref()
            .map(|selector| Self::extract_groups(&access_token.extended_claims, selector))
            .unwrap_or_default();

        permissions.extend(Self::map_items(groups, &self.group_mappings));

        ValidatedAccessToken {
            access_token,
            permissions,
        }
    }

    /// Extract scopes from the value/access token
    fn extract_scopes(value: &Value, selector: &JpQuery) -> Vec<String> {
        js_path_process(selector, value)
            .ok()
            .into_iter()
            .flatten()
            .flat_map(|qr| match qr.val() {
                Value::String(s) => s
                    .split_ascii_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .flat_map(|s| s.split_ascii_whitespace())
                    .map(|s| s.to_string())
                    .collect(),
                _ => vec![],
            })
            .collect()
    }

    /// Extract the groups from the value/access token
    fn extract_groups(value: &Value, selector: &JpQuery) -> Vec<String> {
        js_path_process(selector, value)
            .ok()
            .into_iter()
            .flatten()
            .flat_map(|qr| qr.val().as_str())
            .map(|s| s.to_string())
            .collect()
    }

    fn map_items(
        items: impl IntoIterator<Item = impl AsRef<str>>,
        table: &HashMap<String, Vec<String>>,
    ) -> Vec<String> {
        let mut result = Vec::new();
        for item in items {
            match table.get(item.as_ref()) {
                Some(mapped) => result.extend_from_slice(mapped),
                None => result.push(item.as_ref().to_string()),
            }
        }
        result
    }
}

impl Deref for AuthenticatorClient {
    type Target = Client<Discovered>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    fn assert_scope_mapping(scopes: &str, mappings: &[(&str, &[&str])], expected: &[&str]) {
        let mappings = mappings
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|v| v.to_string()).collect()))
            .collect::<HashMap<String, Vec<String>>>();
        let expected = expected
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>();
        let result = AuthenticatorClient::map_items(scopes.split_whitespace(), &mappings);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scope_mapping() {
        assert_scope_mapping(
            "foo bar baz",
            &[("foo", &["read:foo", "read:bar"] as &[_]), ("baz", &[])],
            &["read:foo", "read:bar", "bar"],
        );
    }

    #[test]
    fn test_no_scope_mapping() {
        assert_scope_mapping("foo bar baz", &[], &["foo", "bar", "baz"]);
    }

    #[test]
    fn test_groups() {
        let token = r#"{
  "sub": "dfbf2b67-eb5e-44e5-8d70-581bf6fa4eff",
  "foo:bar": [
    "manager",
    "reader"
  ],
  "iss": "https://foo/bar",
  "version": 2,
  "client_id": "1m4qeejd6v593cd4bimueircjk",
  "origin_jti": "a49f30ee-a4d3-4f16-aff1-d334ab4e3b00",
  "token_use": "access",
  "scope": "openid",
  "auth_time": 1707311332,
  "exp": 1707314932,
  "iat": 1707311332,
  "jti": "524d55bf-da6b-41a6-91d2-8c16f9dfd198",
  "username": "admin"
}"#;

        let value: Value = serde_json::from_str(token).unwrap();
        const PATH: &str = r#"$['foo:bar'][*]"#;

        let selector = parse_json_path(PATH).unwrap();
        let groups = AuthenticatorClient::extract_groups(&value, &selector);
        assert_eq!(&groups, &["manager", "reader"]);
    }

    #[rstest]
    #[case::scope_only(json!({"scope": "read:document create:document"}), vec!["read:document", "create:document"])]
    #[case::scp_string(json!({"scp": "read:document"}), vec!["read:document"])]
    #[case::scp_array(json!({"scp": ["api://app/read:document", "api://app/create:document"]}), vec!["api://app/read:document", "api://app/create:document"])]
    #[case::both_claims(json!({"scope": "openid profile", "scp": ["api://app/read:document", "api://app/create:document"]}), vec!["openid", "profile", "api://app/read:document", "api://app/create:document"])]
    fn test_extract_scopes(#[case] value: Value, #[case] expected: Vec<&str>) {
        let selector = parse_json_path(config::DEFAULT_SCOPE_SELECTOR).unwrap();
        assert_eq!(
            AuthenticatorClient::extract_scopes(&value, &selector),
            expected
        );
    }

    #[test]
    fn test_extract_scopes_custom_selector() {
        let selector = parse_json_path("$.scp").unwrap();
        let value = json!({
            "scope": "openid profile",
            "scp": ["read:document", "create:document"]
        });
        // Should extract only from scp, ignoring scope
        assert_eq!(
            AuthenticatorClient::extract_scopes(&value, &selector),
            &["read:document", "create:document"]
        );
    }

    #[rstest]
    #[case::null_value(json!({"scope": null}), vec![])]
    #[case::number_value(json!({"scope": 42}), vec![])]
    #[case::boolean_value(json!({"scope": true}), vec![])]
    #[case::object_value(json!({"scope": {"nested": "value"}}), vec![])]
    #[case::empty_string(json!({"scope": ""}), vec![])]
    #[case::empty_array(json!({"scp": []}), vec![])]
    #[case::no_matching_fields(json!({"other": "value"}), vec![])]
    fn test_extract_scopes_non_string_and_empty(#[case] value: Value, #[case] expected: Vec<&str>) {
        let selector = parse_json_path(config::DEFAULT_SCOPE_SELECTOR).unwrap();
        assert_eq!(
            AuthenticatorClient::extract_scopes(&value, &selector),
            expected
        );
    }

    #[rstest]
    #[case::mixed_types(json!({"scp": ["read:document", 42, null, "write:document", true]}), vec!["read:document", "write:document"])]
    #[case::string_multiple_whitespace(json!({"scope": "  read:document   write:document  "}), vec!["read:document", "write:document"])]
    #[case::array_with_whitespace(json!({"scp": ["  read:document write:document  ", "  delete:document  "]}), vec!["read:document", "write:document", "delete:document"])]
    fn test_extract_scopes_edge_cases(#[case] value: Value, #[case] expected: Vec<&str>) {
        let selector = parse_json_path(config::DEFAULT_SCOPE_SELECTOR).unwrap();
        assert_eq!(
            AuthenticatorClient::extract_scopes(&value, &selector),
            expected
        );
    }
}
