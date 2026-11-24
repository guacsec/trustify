use crate::authenticator::claims::AccessTokenClaims;
use openid::{
    Client, Config, Configurable, Jws, Provider,
    biscuit::Empty,
    error::{Expiry, Mismatch, Missing, Validation},
};
use time::{Duration, OffsetDateTime};

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
    let now = OffsetDateTime::now_utc();
    if now.unix_timestamp() < 1504758600 {
        return Err(Validation::Expired(Expiry::NotUnix(now.unix_timestamp())).into());
    }
    let exp = claims.exp;
    if exp <= now.unix_timestamp() {
        return Err(Validation::Expired(
            // OpenID exposes chrono types in its public error variants.
            chrono::DateTime::from_timestamp(exp, 0)
                .map(Expiry::Expires)
                .unwrap_or_else(|| Expiry::NotUnix(exp)),
        )
        .into());
    }

    if let Some(max) = max_age.into() {
        match claims.auth_time {
            Some(time) => {
                // Clamp timestamp subtraction before comparing the token age.
                let age = Duration::seconds(now.unix_timestamp().saturating_sub(time));
                if age >= *max {
                    return Err(Validation::Expired(Expiry::MaxAge(
                        chrono::Duration::try_seconds(age.whole_seconds())
                            .unwrap_or(chrono::Duration::MAX),
                    ))
                    .into());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(expires: i64, auth_time: Option<i64>) -> AccessTokenClaims {
        serde_json::from_value(serde_json::json!({
            "sub": "subject",
            "iss": "https://issuer.example/",
            "iat": 0,
            "exp": expires,
            "auth_time": auth_time,
        }))
        .unwrap()
    }

    #[test]
    fn validates_expiration_with_time_timestamps() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!(validate_token_exp(&claims(now + 3600, None), None).is_ok());
        assert!(validate_token_exp(&claims(now - 3600, None), None).is_err());
    }

    #[test]
    fn enforces_max_age_including_extreme_authentication_timestamps() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let max_age = Duration::minutes(1);
        for auth_time in [None, Some(now - 120), Some(i64::MIN)] {
            assert!(validate_token_exp(&claims(now + 3600, auth_time), &max_age).is_err());
        }
        assert!(validate_token_exp(&claims(now + 3600, Some(now)), &max_age).is_ok());
    }
}
