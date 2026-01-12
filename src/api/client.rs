use reqwest::{Client, RequestBuilder};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: Please check your authentication credentials")]
    Unauthorized,

    #[error("Server error: {0}")]
    ServerError(String),
}

/// API client for Trustify
#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str, token: Option<String>) -> Self {
        // Normalize base URL (remove trailing slash)
        let base_url = base_url.trim_end_matches('/').to_string();

        Self {
            client: Client::new(),
            base_url,
            token,
        }
    }

    /// Build the full API URL
    pub fn url(&self, path: &str) -> String {
        format!("{}/api{}", self.base_url, path)
    }

    /// Add authorization header if token is present
    fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    /// Perform a GET request
    pub async fn get(&self, path: &str) -> Result<String, ApiError> {
        let url = self.url(path);
        let request = self.client.get(&url);
        let response = self.authorize(request).send().await?;

        self.handle_response(response).await
    }

    /// Perform a GET request with query parameters
    pub async fn get_with_query<T: serde::Serialize + ?Sized>(
        &self,
        path: &str,
        query: &T,
    ) -> Result<String, ApiError> {
        let url = self.url(path);
        let request = self.client.get(&url).query(query);
        let response = self.authorize(request).send().await?;

        self.handle_response(response).await
    }

    /// Perform a DELETE request
    pub async fn delete(&self, path: &str) -> Result<String, ApiError> {
        let url = self.url(path);
        let request = self.client.delete(&url);
        let response = self.authorize(request).send().await?;

        self.handle_response(response).await
    }

    async fn handle_response(&self, response: reqwest::Response) -> Result<String, ApiError> {
        let status = response.status();

        if status.is_success() {
            Ok(response.text().await?)
        } else if status.as_u16() == 404 {
            Err(ApiError::NotFound("Resource not found".to_string()))
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ApiError::Unauthorized)
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(ApiError::ServerError(format!("HTTP {}: {}", status, body)))
        }
    }
}
