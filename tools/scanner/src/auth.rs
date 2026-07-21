use crate::error::Error;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Mutex;
use std::time::Instant;

/// OIDC token provider using the `client_credentials` grant.
pub struct OidcTokenProvider {
    client: Client,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    refresh_before_secs: u64,
    state: Mutex<TokenState>,
}

struct TokenState {
    token: Option<String>,
    expires_at: Option<Instant>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct OidcDiscovery {
    token_endpoint: String,
}

impl OidcTokenProvider {
    /// Discover the token endpoint and create a provider.
    pub async fn discover(
        issuer_url: &str,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, Error> {
        let client = Client::new();
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        tracing::info!(url = %discovery_url, "OIDC discovery");

        let discovery: OidcDiscovery = client
            .get(&discovery_url)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| Error::Auth(format!("OIDC discovery failed: {e}")))?
            .json()
            .await?;

        tracing::info!(
            endpoint = %discovery.token_endpoint,
            "OIDC token endpoint discovered"
        );

        Ok(Self {
            client,
            token_endpoint: discovery.token_endpoint,
            client_id,
            client_secret,
            refresh_before_secs: 30,
            state: Mutex::new(TokenState {
                token: None,
                expires_at: None,
            }),
        })
    }

    /// Return a valid access token, refreshing if necessary.
    pub async fn get_token(&self) -> Result<String, Error> {
        // Check if current token is still valid.
        {
            let state = self
                .state
                .lock()
                .map_err(|e| Error::Auth(format!("token state lock poisoned: {e}")))?;
            if let (Some(token), Some(expires_at)) = (&state.token, state.expires_at)
                && Instant::now()
                    < expires_at
                        .checked_sub(std::time::Duration::from_secs(self.refresh_before_secs))
                        .unwrap_or(expires_at)
            {
                return Ok(token.clone());
            }
        }

        // Fetch a new token.
        tracing::debug!("requesting new OIDC token");

        let resp: TokenResponse = self
            .client
            .post(&self.token_endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await?
            .error_for_status()
            .map_err(|e| Error::Auth(format!("token request failed: {e}")))?
            .json()
            .await?;

        let expires_in = resp.expires_in.unwrap_or(300);
        let expires_at = Instant::now() + std::time::Duration::from_secs(expires_in);

        tracing::info!(expires_in, "OIDC token acquired");

        let token = resp.access_token.clone();

        let mut state = self
            .state
            .lock()
            .map_err(|e| Error::Auth(format!("token state lock poisoned: {e}")))?;
        state.token = Some(resp.access_token);
        state.expires_at = Some(expires_at);

        Ok(token)
    }
}
