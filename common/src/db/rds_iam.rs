//! AWS RDS/Aurora IAM database authentication.
//!
//! Instead of a static password, RDS/Aurora can authenticate a connection with a
//! short-lived *authentication token*: a SigV4-presigned request to the `rds-db`
//! service that is passed to PostgreSQL as the connection password. The token is valid
//! for [`RDS_IAM_TOKEN_EXPIRY`] (15 minutes) and must be regenerated for every *new*
//! physical connection — already-established connections keep working past expiry.
//!
//! This is the database counterpart to the S3 token authentication used by the
//! OpenShift Cloud Credential Operator (CCO): the AWS credentials that sign the token
//! come from the AWS default credential provider chain, which on OpenShift resolves to
//! the CCO-provisioned credentials (static keys, or the Web Identity/STS token in
//! `manual` mode). See `docs/design/rds-iam-cco-token-authentication.md`.

use anyhow::{Context, anyhow};
use aws_config::BehaviorVersion;
use aws_credential_types::{Credentials, provider::ProvideCredentials};
use aws_sigv4::{
    http_request::{SignableBody, SignableRequest, SignatureLocation, SigningSettings, sign},
    sign::v4,
};
use url::Url;
use std::time::{Duration, SystemTime};

/// Lifetime of a generated RDS IAM authentication token (AWS fixes this at 15 minutes).
pub const RDS_IAM_TOKEN_EXPIRY: Duration = Duration::from_secs(15 * 60);

/// How long before token expiry a pooled connection's token should be refreshed. Chosen
/// comfortably below [`RDS_IAM_TOKEN_EXPIRY`] so new connections never see a stale token.
pub const RDS_IAM_TOKEN_REFRESH: Duration = Duration::from_secs(10 * 60);

/// The AWS signing service name for RDS IAM database authentication.
const RDS_SIGNING_SERVICE: &str = "rds-db";

/// Generate an RDS/Aurora IAM authentication token for the given database endpoint.
///
/// The returned string is used as the PostgreSQL connection password. Credentials are
/// resolved from the AWS default credential provider chain (environment, profile, Web
/// Identity/STS, IMDS, ...), so no static AWS keys are required in `manual`/STS mode.
///
/// The token is a SigV4-presigned `GET https://{host}:{port}/?Action=connect&DBUser={user}`
/// for the `rds-db` service, with the scheme stripped — this is exactly the format the
/// AWS SDKs' `generate_db_auth_token` helpers produce.
pub async fn generate_rds_iam_token(
    host: &str,
    port: u16,
    username: &str,
    region: &str,
) -> anyhow::Result<String> {
    // Resolve AWS credentials from the default provider chain, pinned to the DB region.
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;
    let provider = sdk_config
        .credentials_provider()
        .ok_or_else(|| anyhow!("no AWS credentials provider available for RDS IAM auth"))?;
    let credentials = provider
        .provide_credentials()
        .await
        .context("failed to resolve AWS credentials for RDS IAM auth")?;

    presign_rds_iam_token(host, port, username, region, credentials, SystemTime::now())
}

/// Presign the RDS IAM authentication token from already-resolved credentials.
///
/// Split out from [`generate_rds_iam_token`] so the signing logic can be exercised with
/// injected credentials — no AWS calls and no process-wide environment mutation.
fn presign_rds_iam_token(
    host: &str,
    port: u16,
    username: &str,
    region: &str,
    credentials: Credentials,
    time: SystemTime,
) -> anyhow::Result<String> {
    let identity = credentials.into();

    // Presign a request to the rds-db service, placing the signature in the query string
    // and setting the token's validity window.
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(RDS_IAM_TOKEN_EXPIRY);

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(RDS_SIGNING_SERVICE)
        .time(time)
        .settings(settings)
        .build()
        .context("failed to build RDS IAM signing parameters")?
        .into();

    // Build the URL via the query-string API so the username (and any other component) is
    // properly percent-encoded. Interpolating it directly would let characters such as `&`,
    // `=` or spaces corrupt the query and produce a token for the wrong user or a rejected
    // one.
    let mut token_url =
        Url::parse(&format!("https://{host}:{port}/")).context("failed to build RDS IAM url")?;
    token_url
        .query_pairs_mut()
        .append_pair("Action", "connect")
        .append_pair("DBUser", username);

    let url = token_url.to_string();
    let signable_request =
        SignableRequest::new("GET", &url, std::iter::empty(), SignableBody::Bytes(&[]))
            .context("failed to build RDS IAM signable request")?;

    let (instructions, _signature) = sign(signable_request, &signing_params)
        .context("failed to sign RDS IAM request")?
        .into_parts();

    // Apply the signing query parameters onto the URL, then drop the scheme to obtain the
    // token in the form PostgreSQL expects as a password.
    {
        let mut pairs = token_url.query_pairs_mut();
        for (name, value) in instructions.params() {
            pairs.append_pair(name, value);
        }
    }

    let token = token_url
        .as_str()
        .strip_prefix("https://")
        .unwrap_or(token_url.as_str())
        .to_string();

    Ok(token)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Deterministic, non-secret credentials for signing in tests. Injected directly so the
    /// tests neither reach AWS nor mutate process-wide environment variables (which would
    /// race with other tests running concurrently).
    fn test_credentials() -> Credentials {
        Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            None,
            "test",
        )
    }

    /// Presign a token against fixed test credentials and assert it has the shape RDS
    /// expects: `host:port/?Action=connect&DBUser=...` plus the SigV4 query parameters,
    /// and no scheme prefix.
    #[test]
    fn token_has_expected_shape() {
        let token = presign_rds_iam_token(
            "db.example.com",
            5432,
            "trustify_user",
            "us-east-1",
            test_credentials(),
            SystemTime::now(),
        )
        .expect("token generation must succeed");

        assert!(
            token.starts_with("db.example.com:5432/?"),
            "unexpected token prefix: {token}"
        );
        assert!(
            !token.contains("https://"),
            "scheme must be stripped: {token}"
        );
        assert!(token.contains("Action=connect"));
        assert!(token.contains("DBUser=trustify_user"));
        assert!(token.contains("X-Amz-Signature="));
        assert!(token.contains("X-Amz-Credential="));
        assert!(token.contains("X-Amz-Expires="));
    }

    /// A username with characters that are significant in a query string must be
    /// percent-encoded so it does not corrupt the `DBUser` parameter.
    #[test]
    fn username_is_url_encoded() {
        let token = presign_rds_iam_token(
            "db.example.com",
            5432,
            "odd&user=name with space",
            "us-east-1",
            test_credentials(),
            SystemTime::now(),
        )
        .expect("token generation must succeed");

        // The raw special characters must not leak into the query untouched.
        assert!(
            token.contains("DBUser=odd%26user%3Dname"),
            "username must be percent-encoded: {token}"
        );
        assert!(
            !token.contains("DBUser=odd&user=name"),
            "unencoded username corrupts the query: {token}"
        );
        // Exactly one DBUser parameter, so signing sees the intended user.
        assert_eq!(
            token.matches("DBUser=").count(),
            1,
            "expected a single DBUser parameter: {token}"
        );
    }
}
