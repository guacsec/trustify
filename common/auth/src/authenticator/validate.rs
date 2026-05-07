use crate::authenticator::claims::AccessTokenClaims;
use chrono::{Duration, Utc};
use openid::{
    Client, Config, Configurable, Jws, Provider,
    biscuit::Empty,
    error::{Expiry, Mismatch, Missing, Validation},
};

pub type AccessToken = Jws<AccessTokenClaims, Empty>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Common(#[from] openid::error::Error),
    #[error("Missing audience - expected: {expected}, actual: {actual}")]
    MissingAudience { expected: String, actual: String },
}

/// This is "fork" of the original [`Client::validate_token`] function, but implemented for
/// validating access tokens.
pub fn validate_token<P: Provider + Configurable>(
    client: &Client<P>,
    token: &AccessToken,
    audience: Option<&str>,
    max_age: Option<&Duration>,
) -> Result<(), Error> {
    let claims = token.payload().map_err(openid::error::Error::Jose)?;
    let config = client.config();

    validate_token_issuer(claims, config)?;
    validate_token_exp(claims, max_age)?;
    validate_token_aud(claims, audience)?;

    Ok(())
}

// from `openid`
fn validate_token_exp<'max_age>(
    claims: &AccessTokenClaims,
    max_age: impl Into<Option<&'max_age Duration>>,
) -> Result<(), openid::error::Error> {
    let now = Utc::now();
    // Now should never be less than the time this code was written!
    if now.timestamp() < 1504758600 {
        panic!("chrono::Utc::now() can never be before this was written!")
    }
    let exp = claims.exp;
    if exp <= now.timestamp() {
        return Err(Validation::Expired(
            chrono::DateTime::from_timestamp(exp, 0)
                .map(Expiry::Expires)
                .unwrap_or_else(|| Expiry::NotUnix(exp)),
        )
        .into());
    }

    if let Some(max) = max_age.into() {
        match claims.auth_time {
            Some(time) => {
                // get the delta as seconds, or use max (which results in "expired")
                let age = chrono::Duration::try_seconds(now.timestamp() - time).unwrap_or(*max);
                if age >= *max {
                    return Err(Validation::Expired(Expiry::MaxAge(age)).into());
                }
            }
            None => return Err(Validation::Missing(Missing::AuthTime).into()),
        }
    }

    Ok(())
}

// from `openid`
fn validate_token_issuer(claims: &AccessTokenClaims, config: &Config) -> Result<(), Error> {
    if claims.iss != config.issuer {
        let expected = config.issuer.as_str().to_string();
        let actual = claims.iss.as_str().to_string();
        return Err(Error::Common(
            Validation::Mismatch(Mismatch::Issuer { expected, actual }).into(),
        ));
    }

    Ok(())
}

pub fn validate_token_aud(
    claims: &AccessTokenClaims,
    required_aud: Option<&str>,
) -> Result<(), Error> {
    let required_aud = match required_aud {
        Some(required_aud) => required_aud,
        None => return Ok(()),
    };

    match &claims.aud {
        Some(aud) => {
            if !aud.contains(required_aud) {
                Err(Error::MissingAudience {
                    expected: required_aud.to_string(),
                    actual: aud
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                })
            } else {
                Ok(())
            }
        }
        None => Err(Error::Common(openid::error::Error::Validation(
            Validation::Missing(Missing::Audience),
        ))),
    }
}
