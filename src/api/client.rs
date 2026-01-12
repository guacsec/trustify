use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, RequestBuilder, StatusCode};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::auth;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;

#[derive(Error, Debug, Clone)]
pub enum ApiError {
    #[error("Request failed: {0}")]
    RequestError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: Please check your authentication credentials")]
    Unauthorized,

    #[error("Token expired")]
    TokenExpired,

    #[error("Server timeout - please retry")]
    Timeout,

    #[error("Server error: {0}")]
    ServerError(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            ApiError::Timeout
        } else {
            ApiError::RequestError(e.to_string())
        }
    }
}

/// Authentication credentials for token refresh
#[derive(Clone)]
pub struct AuthCredentials {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
}

/// API client for Trustify with retry and token refresh support
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    token: Arc<RwLock<Option<String>>>,
    auth_credentials: Option<AuthCredentials>,
}

impl ApiClient {
    pub fn new(
        base_url: &str,
        token: Option<String>,
        auth_credentials: Option<AuthCredentials>,
    ) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_else(|_| Client::new()),
            base_url,
            token: Arc::new(RwLock::new(token)),
            auth_credentials,
        }
    }

    /// Build the full API URL
    pub fn url(&self, path: &str) -> String {
        format!("{}/api{}", self.base_url, path)
    }

    /// Add authorization header if token is present
    async fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        let token = self.token.read().await;
        match &*token {
            Some(t) => request.bearer_auth(t),
            None => request,
        }
    }

    /// Refresh the token using stored credentials
    async fn refresh_token(&self) -> Result<(), ApiError> {
        let creds = self
            .auth_credentials
            .as_ref()
            .ok_or(ApiError::Unauthorized)?;

        eprintln!("Token expired, refreshing...");

        match auth::get_token(&creds.token_url, &creds.client_id, &creds.client_secret).await {
            Ok(new_token) => {
                let mut token = self.token.write().await;
                *token = Some(new_token);
                eprintln!("Token refreshed successfully");
                Ok(())
            }
            Err(e) => {
                eprintln!("Failed to refresh token: {}", e);
                Err(ApiError::Unauthorized)
            }
        }
    }

    /// Perform a GET request with retry logic
    pub async fn get(&self, path: &str) -> Result<String, ApiError> {
        self.execute_with_retry(|| async {
            let url = self.url(path);
            let request = self.client.get(&url);
            let response = self.authorize(request).await.send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Perform a GET request with query parameters and retry logic
    pub async fn get_with_query<T: serde::Serialize + ?Sized + Sync>(
        &self,
        path: &str,
        query: &T,
    ) -> Result<String, ApiError> {
        self.execute_with_retry(|| async {
            let url = self.url(path);
            let request = self.client.get(&url).query(query);
            let response = self.authorize(request).await.send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Perform a DELETE request with retry logic
    pub async fn delete(&self, path: &str) -> Result<String, ApiError> {
        self.execute_with_retry(|| async {
            let url = self.url(path);
            let request = self.client.delete(&url);
            let response = self.authorize(request).await.send().await?;
            self.handle_response(response).await
        })
        .await
    }

    /// Execute a request with retry logic for timeouts and token refresh
    async fn execute_with_retry<F, Fut>(&self, f: F) -> Result<String, ApiError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<String, ApiError>>,
    {
        let mut last_error = ApiError::RequestError("No attempts made".to_string());
        let mut token_refreshed = false;

        for attempt in 0..MAX_RETRIES {
            match f().await {
                Ok(result) => return Ok(result),
                Err(ApiError::TokenExpired) => {
                    if !token_refreshed
                        && self.auth_credentials.is_some()
                        && self.refresh_token().await.is_ok()
                    {
                        token_refreshed = true;
                        continue; // Retry with new token
                    }
                    return Err(ApiError::Unauthorized);
                }
                Err(ApiError::Timeout) | Err(ApiError::ServerError(_))
                    if attempt < MAX_RETRIES - 1 =>
                {
                    let delay = RETRY_DELAY_MS * (attempt as u64 + 1);
                    eprintln!(
                        "Request failed, retrying in {}ms... (attempt {}/{})",
                        delay,
                        attempt + 1,
                        MAX_RETRIES
                    );
                    sleep(Duration::from_millis(delay)).await;
                    last_error = ApiError::Timeout;
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error)
    }

    async fn handle_response(&self, response: reqwest::Response) -> Result<String, ApiError> {
        let status = response.status();

        if status.is_success() {
            Ok(response.text().await?)
        } else if status == StatusCode::NOT_FOUND {
            Err(ApiError::NotFound("Resource not found".to_string()))
        } else if status == StatusCode::UNAUTHORIZED {
            Err(ApiError::TokenExpired)
        } else if status == StatusCode::FORBIDDEN {
            Err(ApiError::Unauthorized)
        } else if status == StatusCode::GATEWAY_TIMEOUT || status == StatusCode::REQUEST_TIMEOUT {
            Err(ApiError::Timeout)
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(ApiError::ServerError(format!("HTTP {}: {}", status, body)))
        }
    }
}
