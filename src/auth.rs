use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Failed to connect to SSO server: {0}")]
    ConnectionError(#[from] reqwest::Error),

    #[error("Authentication failed: Invalid client_id, client_secret, or SSO URL. Please verify your credentials.")]
    AuthenticationFailed,

    #[error("SSO server returned an error: {0}")]
    ServerError(String),
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Retrieves an OAuth2 access token using client credentials grant
pub async fn get_token(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, AuthError> {
    let client = Client::new();

    let response = client
        .post(token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await?;

    if response.status().is_success() {
        let token_response: TokenResponse = response.json().await?;
        Ok(token_response.access_token)
    } else if response.status().as_u16() == 401 || response.status().as_u16() == 400 {
        // Try to get error details
        if let Ok(error_response) = response.json::<ErrorResponse>().await {
            if error_response.error == "invalid_client"
                || error_response.error == "unauthorized_client"
            {
                return Err(AuthError::AuthenticationFailed);
            }
            let msg = error_response
                .error_description
                .unwrap_or(error_response.error);
            return Err(AuthError::ServerError(msg));
        }
        Err(AuthError::AuthenticationFailed)
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AuthError::ServerError(format!("HTTP {}: {}", status, body)))
    }
}
