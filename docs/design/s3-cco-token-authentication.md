# S3 Storage — CCO Token Authentication (OpenShift STS / Web Identity)

## Purpose

Trustify can store documents in an S3-compatible object store. On OpenShift,
the [Cloud Credential Operator (CCO)](https://docs.openshift.com/container-platform/latest/authentication/managing_cloud_provider_credentials/about-cloud-credential-operator.html)
can provision the credentials the pod uses to reach S3, instead of an administrator
creating a long-lived access-key / secret-key pair by hand.

CCO supports several modes. They fall into two categories from trustify's point of view:

| Category | CCO mode(s) | What the pod receives |
|----------|-------------|-----------------------|
| **Static credentials** | `mint`, `passthrough`, `default` | A secret with `aws_access_key_id` / `aws_secret_access_key`, injected as `TRUSTD_S3_ACCESS_KEY` / `TRUSTD_S3_SECRET_KEY`. |
| **Token authentication** | `manual` (STS / Web Identity) | A projected ServiceAccount token, a role ARN, and a mounted AWS credentials file. **No** static access/secret keys. |

This document describes how trustify's S3 backend obtains credentials in each case,
and specifically the support for **token authentication** (the `manual`/STS mode).

## Background: how CCO manual/STS mode delivers credentials

When the kubernetes operator deploys trustify with `cloudProvider: aws` and `ccoMode: manual`,
it wires the following into the `server` and `importer` pods (see the operator's
`helm-charts/.../templates/helpers/_cco.tpl` and `_storage.tpl`):

* A **projected ServiceAccount token** mounted at
  `/var/run/secrets/openshift/serviceaccount/token` (audience `openshift`, ~1h expiry).
* The **CCO credentials secret** mounted at `/var/run/secrets/cloud`, containing an
  INI-style `credentials` file with a `role_arn` / `web_identity_token_file` profile.
* The standard AWS SDK environment variables:
  * `AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/openshift/serviceaccount/token`
  * `AWS_ROLE_ARN=<stsIAMRoleARN>`
  * `AWS_SHARED_CREDENTIALS_FILE=/var/run/secrets/cloud/credentials`
* Crucially, `TRUSTD_S3_ACCESS_KEY` and `TRUSTD_S3_SECRET_KEY` are **omitted** — the AWS
  SDK is expected to obtain short-lived credentials itself via
  `AssumeRoleWithWebIdentity` (STS), exchanging the ServiceAccount token for temporary
  credentials that it refreshes automatically before expiry.

## How trustify's S3 backend selects credentials

The selection happens in `S3Backend::new` (`modules/storage/src/service/s3.rs`).
The AWS S3 client is built from a hand-constructed `aws_sdk_s3::config::Builder`. That
builder does **not** wire up any credential provider chain on its own (unlike a client
built from `aws_config::defaults(..)`), so the backend must set one explicitly:

```rust
config = match access_key.zip(secret_key) {
    // 1. Static credentials: explicit keys, or CCO mint/passthrough/default mode.
    Some((key_id, access_key)) => {
        let credentials = Credentials::new(key_id, access_key, None, None, "config");
        config.credentials_provider(credentials)
    }
    // 2. No static keys, but the AWS credential environment is present: fall back to the
    //    AWS default credential provider chain, which includes the Web Identity Token
    //    provider used by CCO manual/STS mode.
    None if aws_credentials_configured() => {
        let shared = aws_config::defaults(BehaviorVersion::latest()).load().await;
        match shared.credentials_provider() {
            Some(provider) => config.credentials_provider(provider),
            None => config,
        }
    }
    // 3. No static keys and no AWS credential environment: skip AWS entirely.
    None => config,
};
```

`aws_credentials_configured()` (in `trustify_common::aws`) is a cheap, side-effect-free
check for the standard AWS credential environment variables (`AWS_ACCESS_KEY_ID`,
`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`, `AWS_SHARED_CREDENTIALS_FILE`,
`AWS_PROFILE`, the container-credential URIs, …). When none are set there is no point
loading the default chain — it would resolve to nothing and any request would go out
unsigned — so the backend skips AWS and leaves the client without a credentials provider.
Credentials available *only* from IMDS are not detected, which is acceptable for the
operator-managed deployments where these variables are always set.

* **Static path** — unchanged behaviour. Both keys must be provided together (validated
  earlier in `S3Backend::new`; the config-level `requires` in `S3Config` enforces the
  same at parse time). Used for manually supplied keys and CCO `mint`/`passthrough`/
  `default` modes.
* **Fallback path** — when no keys are given, the backend loads the AWS default
  credential provider chain and installs its resolved credentials provider on the S3
  client config. The chain includes the **Web Identity Token provider**, which reads
  `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (and the profile in
  `AWS_SHARED_CREDENTIALS_FILE`) and performs `AssumeRoleWithWebIdentity`. This is what
  makes CCO manual/STS token authentication work.

The credentials are resolved lazily on first use and refreshed by the SDK, so no static
secret is ever held by trustify.

### Why this was needed

Before this change, the `else` branch did not exist: when no static keys were supplied
the client was left with **no credentials provider at all**. In CCO manual/STS mode —
which intentionally omits `TRUSTD_S3_ACCESS_KEY` / `TRUSTD_S3_SECRET_KEY` — requests to
S3 would go out unsigned and fail. Token authentication therefore did not work until the
default-chain fallback was added.


## Configuration summary

When the storage strategy is `s3`:

* If **both** `TRUSTD_S3_ACCESS_KEY` and `TRUSTD_S3_SECRET_KEY` are set, they are used as
  static credentials. Setting only one of the two is an error.
* If **neither** is set, the AWS default credential provider chain is used. This includes
  the Web Identity Token provider (`AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`, and/or
  `AWS_SHARED_CREDENTIALS_FILE`), which enables **token authentication** via OpenShift's
  Cloud Credential Operator in `manual`/STS mode. See
  [docs/design/s3-cco-token-authentication.md](design/s3-cco-token-authentication.md).

No new trustify configuration flags are introduced. Behaviour is driven entirely by
whether the static keys are present:

| `TRUSTD_S3_ACCESS_KEY` / `TRUSTD_S3_SECRET_KEY` | Credential source |
|--------------------------------------------------|-------------------|
| both set | Static credentials (the given keys) |
| both unset, AWS credential env present | AWS default credential provider chain — env/profile/**web-identity (STS)** |
| both unset, no AWS credential env | No credentials provider — AWS is not engaged |

The web-identity path relies on the standard AWS SDK environment variables
(`AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_SHARED_CREDENTIALS_FILE`), which the
kubernetes operator sets automatically in `manual` mode. When running outside the operator,
set those variables yourself to use token authentication.

## Testing

* `modules/storage/src/service/s3.rs` — `no_static_credentials_uses_default_chain`
  asserts that constructing the backend without static keys succeeds (the chain is
  resolved lazily, so construction must not fail even with no AWS credentials present).
* `partial_credentials_validation` continues to assert that supplying only one of the
  two static keys is rejected.
* End-to-end validation of the STS exchange itself requires a real OpenShift cluster
  with CCO (or an equivalent web-identity setup) and is out of scope for the unit tests.

## Related: RDS IAM database authentication

The kubernetes operator also offers **token-based database authentication** via
`ccoRds.enabled`, setting `TRUSTD_DB_IAM_AUTH=true` and `TRUSTD_DB_REGION`, providing AWS
credentials, and omitting `database.password`. This is the database counterpart to the S3
token-auth path described here and is documented separately in
[docs/design/rds-iam-cco-token-authentication.md](rds-iam-cco-token-authentication.md).
