use clap::Args;

/// Configuration for connecting to Trustify API
#[derive(Args, Clone)]
pub struct Config {
    /// Trustify API URL (required)
    #[arg(short = 'u', long = "url", env = "TRUSTIFY_URL")]
    pub url: String,

    /// SSO URL for authentication
    #[arg(long = "sso-url", env = "TRUSTIFY_SSO_URL")]
    pub sso_url: Option<String>,

    /// OAuth2 Client ID
    #[arg(long = "client-id", env = "TRUSTIFY_CLIENT_ID")]
    pub client_id: Option<String>,

    /// OAuth2 Client Secret
    #[arg(long = "client-secret", env = "TRUSTIFY_CLIENT_SECRET")]
    pub client_secret: Option<String>,
}

impl Config {
    /// Returns true if authentication credentials are configured
    pub fn has_auth(&self) -> bool {
        self.sso_url.is_some() && self.client_id.is_some() && self.client_secret.is_some()
    }

    /// Returns the auth credentials if all are present
    pub fn auth_credentials(&self) -> Option<(&str, &str, &str)> {
        match (&self.sso_url, &self.client_id, &self.client_secret) {
            (Some(sso), Some(id), Some(secret)) => Some((sso.as_str(), id.as_str(), secret.as_str())),
            _ => None,
        }
    }
}
