//! OpenID Connect tools

use super::user::UserDetails;
use biscuit::SingleOrMultiple;
use openid::CompactJson;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// An OIDC access token, containing the claims that we need.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessTokenClaims {
    #[serde(default)]
    pub azp: Option<String>,
    pub sub: String,
    pub iss: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<SingleOrMultiple<String>>,

    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub auth_time: Option<i64>,

    #[serde(flatten)]
    pub extended_claims: Value,
}

impl CompactJson for AccessTokenClaims {}

/// A validated access token, including post-processing according to our configuration.
#[derive(Clone, Debug)]
pub struct ValidatedAccessToken {
    pub access_token: AccessTokenClaims,
    pub permissions: Vec<String>,
}

impl From<ValidatedAccessToken> for UserDetails {
    fn from(token: ValidatedAccessToken) -> Self {
        Self {
            id: token.access_token.sub,
            permissions: token.permissions,
        }
    }
}
