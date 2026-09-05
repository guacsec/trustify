//! Detection of AWS credential configuration.
//!
//! Both the S3 storage backend and the RDS/Aurora IAM database authentication path fall
//! back to the AWS default credential provider chain when no static credentials are
//! supplied. Engaging that chain has a cost: `aws_config::defaults(..).load()` spins up
//! providers and, for the Web Identity/STS path, can reach out to AWS. When nothing in the
//! environment points at an AWS credential source there is no point paying that cost — the
//! chain would resolve to nothing anyway and any AWS request would go out unsigned.
//!
//! This module provides a cheap, side-effect-free check for whether the environment is set
//! up for the AWS default chain, so callers can skip AWS entirely when it isn't configured.

use std::env;

/// Environment variables whose presence indicates the AWS default credential provider chain
/// has a usable credential source configured.
///
/// This covers the sources relevant to trustify's deployments:
/// * static keys in the environment (`AWS_ACCESS_KEY_ID`),
/// * Web Identity/STS as provisioned by the OpenShift Cloud Credential Operator in `manual`
///   mode (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`),
/// * a shared credentials/config file or named profile (`AWS_SHARED_CREDENTIALS_FILE`,
///   `AWS_CONFIG_FILE`, `AWS_PROFILE`),
/// * container-provided credentials (ECS/EKS pod identity).
///
/// Note: credentials available *only* from the EC2 instance metadata service (IMDS) expose
/// no environment variable, so a bare EC2 deployment that relies on an instance-profile role
/// is not detected by these variables alone. Because IMDS cannot be probed cheaply or without
/// a network side effect, such deployments opt in explicitly via [`AWS_USE_IMDS_ENV_VAR`].
const AWS_CREDENTIAL_ENV_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_PROFILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
];

/// Opt-in for engaging the AWS default credential provider chain when credentials come from a
/// source that exposes no environment variable — in practice the EC2 instance metadata service
/// (IMDS) on a deployment using an instance-profile role.
///
/// Detecting IMDS requires a network call to the metadata endpoint, which defeats the point of
/// this cheap, side-effect-free check and is slow to time out when *not* on EC2. Rather than
/// probe, we let the operator assert that the default chain has a usable source by setting this
/// variable to a truthy value (`1`, `true`, `yes`, `on`). The SDK then resolves credentials via
/// the full chain, including IMDS.
const AWS_USE_IMDS_ENV_VAR: &str = "TRUSTD_AWS_USE_IMDS";

/// Returns `true` if the environment is configured for the AWS default credential provider
/// chain: either one of [`AWS_CREDENTIAL_ENV_VARS`] is present, or the caller has opted into
/// IMDS via [`AWS_USE_IMDS_ENV_VAR`].
///
/// Use this to decide whether to engage AWS at all: when it returns `false`, callers should
/// skip loading the default chain and avoid making AWS-authenticated connections.
pub fn aws_credentials_configured() -> bool {
    credentials_configured_with(|name| env::var_os(name))
}

/// Core of [`aws_credentials_configured`], parameterised over how a variable is looked up so it
/// can be exercised without mutating process-wide environment state.
fn credentials_configured_with(mut get: impl FnMut(&str) -> Option<std::ffi::OsString>) -> bool {
    if AWS_CREDENTIAL_ENV_VARS
        .iter()
        .any(|name| get(name).is_some_and(|value| !value.is_empty()))
    {
        return true;
    }

    // No credential env var is set; honour the explicit IMDS opt-in.
    get(AWS_USE_IMDS_ENV_VAR)
        .and_then(|value| value.into_string().ok())
        .is_some_and(|value| value == "true")
}

#[cfg(test)]
mod test {
    use super::*;
    use std::ffi::OsString;

    /// Build a lookup that reports the given variables as set to a non-empty value.
    fn set_vars<'a>(vars: &'a [(&'a str, &'a str)]) -> impl FnMut(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| OsString::from(*v))
        }
    }

    #[test]
    fn none_set_is_not_configured() {
        assert!(!credentials_configured_with(|_| None));
    }

    #[test]
    fn web_identity_is_configured() {
        assert!(credentials_configured_with(set_vars(&[(
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "/var/run/token"
        )])));
    }

    #[test]
    fn static_key_is_configured() {
        assert!(credentials_configured_with(set_vars(&[(
            "AWS_ACCESS_KEY_ID",
            "AKID"
        )])));
    }

    #[test]
    fn empty_value_is_not_configured() {
        assert!(!credentials_configured_with(set_vars(&[(
            "AWS_ACCESS_KEY_ID",
            ""
        )])));
    }

    #[test]
    fn unrelated_var_is_not_configured() {
        assert!(!credentials_configured_with(set_vars(&[(
            "SOME_OTHER_VAR",
            "x"
        )])));
    }

    #[test]
    fn imds_opt_in_is_configured() {
        assert!(
            credentials_configured_with(set_vars(&[(AWS_USE_IMDS_ENV_VAR, "true")])),
            "expected \"true\" to opt into IMDS"
        );
    }

    #[test]
    fn imds_opt_in_falsey_is_not_configured() {
        for value in ["false", "TRUE", "1", "yes", "on", " true ", ""] {
            assert!(
                !credentials_configured_with(set_vars(&[(AWS_USE_IMDS_ENV_VAR, value)])),
                "expected {value:?} not to opt into IMDS"
            );
        }
    }
}
