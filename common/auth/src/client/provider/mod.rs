mod bearer_token;
mod openid;

pub use self::bearer_token::*;
pub use self::openid::*;

use super::error::Error;
use async_trait::async_trait;
use base64::{prelude::BASE64_STANDARD, write::EncoderStringWriter};
use std::fmt::Debug;
use std::io::Write;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum Credentials {
    Bearer(String),
    Basic(String, Option<String>),
}

impl Credentials {
    /// Turn this into a value suitable for an `Authorization` header
    pub fn to_authorization_value(&self) -> String {
        match self {
            Self::Bearer(token) => format!("Bearer {token}"),
            Self::Basic(username, password) => {
                let mut encoder = EncoderStringWriter::new(&BASE64_STANDARD);
                let _ = write!(encoder, "{username}:");
                if let Some(password) = password {
                    let _ = write!(encoder, "{password}");
                }
                encoder.into_inner()
            }
        }
    }
}

/// A provider for access credentials (mostly access tokens).
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error>;
}

#[async_trait]
impl<T> TokenProvider for Arc<T>
where
    T: TokenProvider,
{
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        self.as_ref().provide_access_token().await
    }
}

#[async_trait]
impl<T> TokenProvider for &Arc<T>
where
    T: TokenProvider,
{
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        self.as_ref().provide_access_token().await
    }
}

#[async_trait]
impl TokenProvider for Arc<dyn TokenProvider> {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        self.as_ref().provide_access_token().await
    }
}

/// A token provider which does not provide tokens.
#[derive(Debug, Clone, Copy)]
pub struct NoTokenProvider;

#[async_trait]
impl TokenProvider for NoTokenProvider {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(None)
    }
}

#[async_trait]
impl TokenProvider for () {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(None)
    }
}

#[async_trait]
impl<T> TokenProvider for Option<T>
where
    T: TokenProvider + Sync,
{
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        match self {
            None => Ok(None),
            Some(provider) => provider.provide_access_token().await,
        }
    }
}

#[async_trait]
impl TokenProvider for String {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(Some(Credentials::Bearer(self.clone())))
    }
}

#[cfg(feature = "actix")]
use actix_web_httpauth::extractors::bearer::BearerAuth;

#[cfg(feature = "actix")]
#[async_trait]
impl TokenProvider for BearerAuth {
    async fn provide_access_token(&self) -> Result<Option<Credentials>, Error> {
        Ok(Some(Credentials::Bearer(self.token().to_string())))
    }
}
