use crate::{authenticator::default_scope_mappings, devmode};
use clap::ArgAction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, clap::Args)]
#[command(
    rename_all_env = "SCREAMING_SNAKE_CASE",
    next_help_heading = "Authentication"
)]
pub struct AuthenticatorConfigArguments {
    /// Flag to disable authentication, default is on.
    #[arg(
        id = "authentication-disabled",
        default_value_t = false,
        long = "authentication-disabled",
        env = "AUTHENTICATION_DISABLED"
    )]
    pub disabled: bool,

    #[command(flatten)]
    pub clients: SingleAuthenticatorClientConfig,
}

#[derive(
    Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorConfig {
    pub clients: Vec<AuthenticatorClientConfig>,
}

impl AuthenticatorConfig {
    /// Create settings when using `--devmode`.
    pub fn devmode() -> Self {
        Self {
            clients: devmode::client_ids()
                .iter()
                .map(|client_id| AuthenticatorClientConfig {
                    client_id: client_id.clone(),
                    issuer_url: devmode::issuer_url(),
                    scope_mappings: default_scope_mappings(),
                    additional_permissions: Default::default(),
                    required_audience: None,
                    group_selector: None,
                    group_mappings: Default::default(),
                    tls_insecure: false,
                    tls_ca_certificates: Default::default(),
                })
                .collect(),
        }
    }
}

impl From<AuthenticatorConfigArguments> for Option<AuthenticatorConfig> {
    fn from(value: AuthenticatorConfigArguments) -> Self {
        match value.disabled {
            true => None,
            false => Some(AuthenticatorConfig {
                clients: value.clients.expand().collect(),
            }),
        }
    }
}

/// A structure to configure multiple clients ID in a simple way
#[derive(Clone, Debug, Default, PartialEq, Eq, clap::Args)]
#[command(next_help_heading = "Authentication settings")]
pub struct SingleAuthenticatorClientConfig {
    /// The client IDs to allow
    #[arg(env = "AUTHENTICATOR_OIDC_CLIENT_IDS", long = "authentication-client-id", action = ArgAction::Append, value_delimiter = ',')]
    pub client_ids: Vec<String>,

    /// The issuer URL of the clients.
    #[arg(
        env = "AUTHENTICATOR_OIDC_ISSUER_URL",
        long = "authentication-issuer-url",
        default_value = "",
        required = false
    )]
    pub issuer_url: String,

    /// Enforce an "audience" to be present in the access token
    #[arg(
        env = "AUTHENTICATOR_OIDC_REQUIRED_AUDIENCE",
        long = "authentication-required-audience"
    )]
    pub required_audience: Option<String>,

    /// Allow insecure TLS connections with the SSO server (this is insecure!)
    #[arg(
        env = "AUTHENTICATOR_OIDC_TLS_INSECURE",
        default_value_t = false,
        long = "authentication-tls-insecure"
    )]
    pub tls_insecure: bool,

    /// Enable additional TLS certificates for communication with the SSO server
    #[arg(env = "AUTHENTICATOR_OIDC_TLS_CA_CERTIFICATES", long = "authentication-tls-certificate", action = ArgAction::Append)]
    pub tls_ca_certificates: Vec<PathBuf>,
}

/// Configuration for OIDC client used to authenticate on the server side
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorClientConfig {
    /// The ID of the client
    pub client_id: String,
    /// The issuer URL
    pub issuer_url: String,

    /// Mapping table for scopes returned by the issuer to permissions.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub scope_mappings: HashMap<String, Vec<String>>,

    /// Additional scopes which get added for client
    ///
    /// This can be useful if a client is considered to only provide identities which are supposed
    /// to have certain scopes, but don't provide them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde(alias = "additional_scopes")]
    pub additional_permissions: Vec<String>,

    /// Enforce an audience claim (`aud`) for tokens.
    ///
    /// If present, the token must have one matching `aud` claim.
    #[serde(default)]
    pub required_audience: Option<String>,

    /// JSON path extracting a list of groups from the access token
    #[serde(default)]
    pub group_selector: Option<String>,

    /// Mapping table for groups returned found through the `groups_selector` to permissions.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub group_mappings: HashMap<String, Vec<String>>,

    /// Ignore TLS checks when contacting the issuer
    #[serde(default)]
    pub tls_insecure: bool,

    /// Add additional certificates as trust anchor for contacting the issuer
    #[serde(default)]
    pub tls_ca_certificates: Vec<PathBuf>,
}

impl SingleAuthenticatorClientConfig {
    pub fn expand(self) -> impl Iterator<Item = AuthenticatorClientConfig> {
        self.client_ids
            .into_iter()
            .map(move |client_id| AuthenticatorClientConfig {
                client_id,
                issuer_url: self.issuer_url.clone(),
                tls_ca_certificates: self.tls_ca_certificates.clone(),
                tls_insecure: self.tls_insecure,
                required_audience: self.required_audience.clone(),
                scope_mappings: default_scope_mappings(),
                group_selector: None,
                group_mappings: Default::default(),
                additional_permissions: Default::default(),
            })
    }
}
