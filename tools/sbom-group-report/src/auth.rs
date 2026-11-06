//! OIDC client-credentials tokens for the Trustify client.

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use reqwest::Url;
use trustify_client::AccessTokenProvider;

/// Refresh this long before the token actually expires.
const REFRESH_MARGIN: Duration = Duration::from_secs(30);

/// Fetches access tokens with the OIDC `client_credentials` grant and caches
/// them until shortly before they expire.
///
/// `trustify-client` asks for a token on every request, so a long report run
/// keeps working past the token lifetime of the identity provider.
pub struct ClientCredentials {
    http: reqwest::Client,
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    use_basic_auth: bool,
    cached: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl ClientCredentials {
    /// Discover the issuer's token endpoint and prepare the provider.
    pub async fn discover(
        issuer_url: &str,
        client_id: String,
        client_secret: String,
    ) -> anyhow::Result<Self> {
        let issuer = parse_secure_url(issuer_url, "ISSUER_URL", false)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let discovery = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let metadata: serde_json::Value = http
            .get(&discovery)
            .send()
            .await
            .with_context(|| format!("fetching {discovery}"))?
            .error_for_status()?
            .json()
            .await
            .with_context(|| format!("parsing {discovery}"))?;

        if metadata["issuer"].as_str() != Some(issuer_url) {
            bail!("OIDC discovery issuer does not match ISSUER_URL");
        }
        let Some(token_endpoint) = metadata["token_endpoint"].as_str() else {
            bail!("no token_endpoint in the discovery document at {discovery}");
        };
        let token_url = parse_secure_url(token_endpoint, "token_endpoint", true)?;
        if issuer.scheme() == "https" && token_url.scheme() != "https" {
            bail!("token_endpoint must use HTTPS when ISSUER_URL uses HTTPS");
        }

        let methods = metadata.get("token_endpoint_auth_methods_supported");
        let supports = |method| {
            methods
                .and_then(|value| value.as_array())
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(method)))
        };
        let use_basic_auth = methods.is_none() || supports("client_secret_basic");
        if !use_basic_auth && !supports("client_secret_post") {
            bail!("OIDC issuer must support client_secret_basic or client_secret_post");
        }

        Ok(Self {
            http,
            token_endpoint: token_url.to_string(),
            client_id,
            client_secret,
            use_basic_auth,
            cached: tokio::sync::Mutex::new(None),
        })
    }

    async fn fetch(&self) -> anyhow::Result<(String, Instant)> {
        let request = self.http.post(&self.token_endpoint);
        let request = if self.use_basic_auth {
            // OAuth Basic credentials are form-encoded before Base64 (RFC 6749 §2.3.1).
            let encoded = serde_urlencoded::to_string([(&self.client_id, &self.client_secret)])?;
            let (id, secret) = encoded
                .split_once('=')
                .context("encoding OIDC credentials")?;
            request
                .basic_auth(id, Some(secret))
                .form(&[("grant_type", "client_credentials")])
        } else {
            request.form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
        };
        let response: serde_json::Value = request
            .send()
            .await
            .with_context(|| format!("requesting a token from {}", self.token_endpoint))?
            .error_for_status()
            .context("the identity provider rejected the client credentials")?
            .json()
            .await
            .context("parsing the token response")?;

        let Some(token) = response["access_token"]
            .as_str()
            .filter(|token| !token.is_empty())
        else {
            bail!(
                "no access_token in the response from {}",
                self.token_endpoint
            );
        };
        if !response["token_type"]
            .as_str()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("bearer"))
        {
            bail!("OIDC token response token_type must be Bearer");
        }
        // Treat a missing or unusable expires_in as "expired immediately",
        // which costs a token request per API call but never sends a stale one.
        let lifetime = Duration::from_secs(response["expires_in"].as_u64().unwrap_or(0));

        let valid_until = Instant::now()
            .checked_add(lifetime.saturating_sub(REFRESH_MARGIN))
            .context("OIDC expires_in is too large")?;
        Ok((token.to_owned(), valid_until))
    }
}

/// Parse an absolute HTTP(S) URL, rejecting embedded credentials and fragments.
///
/// `allow_query` permits a query string, which an OIDC token endpoint may carry.
pub(crate) fn parse_url(raw: &str, name: &str, allow_query: bool) -> anyhow::Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("invalid {name}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!allow_query && url.query().is_some())
    {
        bail!("{name} must be an absolute HTTP(S) URL without credentials or a fragment");
    }
    Ok(url)
}

/// True when the URL points at the local machine, where plain HTTP cannot leak
/// onto a network.
pub(crate) fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

/// Parse a URL that will carry the client secret, so plain HTTP is refused
/// anywhere but loopback.
pub(crate) fn parse_secure_url(raw: &str, name: &str, allow_query: bool) -> anyhow::Result<Url> {
    let url = parse_url(raw, name, allow_query)?;
    if url.scheme() != "https" && !is_loopback(&url) {
        bail!("{name} must use HTTPS outside loopback");
    }
    Ok(url)
}

#[async_trait::async_trait]
impl AccessTokenProvider for ClientCredentials {
    async fn access_token(&self) -> Result<Option<String>, String> {
        let mut cached = self.cached.lock().await;
        if let Some((token, valid_until)) = cached.as_ref()
            && Instant::now() < *valid_until
        {
            return Ok(Some(token.clone()));
        }

        // Errors reach the user through the failing API call; the secret and
        // the token itself are never part of the message.
        let (token, valid_until) = self.fetch().await.map_err(|err| format!("{err:#}"))?;
        *cached = Some((token.clone(), valid_until));
        Ok(Some(token))
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_secure_url, parse_url};

    #[test]
    fn credential_urls_require_https_except_on_loopback() {
        for url in [
            "https://identity.example/realm",
            "http://localhost:8090/realm",
            "http://127.0.0.2/realm",
            "http://[::1]/realm",
        ] {
            assert!(parse_secure_url(url, "issuer", false).is_ok(), "{url}");
        }
        for url in [
            "http://identity.example/realm",
            "http://localhost.example/realm",
        ] {
            assert!(parse_secure_url(url, "issuer", false).is_err(), "{url}");
        }
        assert!(
            parse_secure_url(
                "https://identity.example/token?audience=report",
                "token",
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn the_trustify_url_allows_plain_http_anywhere() {
        // Internal deployments are routinely plain HTTP behind a gateway.
        assert!(parse_url("http://trustify.internal:8080", "TRUSTIFY_URL", false).is_ok());
    }

    #[test]
    fn malformed_urls_are_rejected_by_both() {
        for url in [
            "https://user:password@identity.example/realm",
            "https://identity.example/realm#fragment",
            "https://identity.example/realm?query",
            "file:///realm",
            "not-a-url",
        ] {
            assert!(parse_url(url, "url", false).is_err(), "{url}");
            assert!(parse_secure_url(url, "url", false).is_err(), "{url}");
        }
    }
}
