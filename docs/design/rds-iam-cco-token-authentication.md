# RDS/Aurora — CCO Token Authentication (IAM database authentication)

## Purpose

Trustify stores its data in a PostgreSQL database. On AWS, that database can be an
RDS or Aurora PostgreSQL instance, and instead of a static password RDS supports
[**IAM database authentication**](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html):
the client authenticates with a short-lived *authentication token* generated from AWS
credentials, rather than a long-lived database password.

On OpenShift, the [Cloud Credential Operator (CCO)](https://docs.openshift.com/container-platform/latest/authentication/managing_cloud_provider_credentials/about-cloud-credential-operator.html)
can provision the AWS credentials the pod uses to generate that token. This is the
database counterpart to the S3 token authentication described in
[s3-cco-token-authentication.md](s3-cco-token-authentication.md): the same CCO-provisioned
credentials (static keys, or the Web Identity/STS token in `manual` mode) that sign S3
requests also sign the RDS IAM token.

| Category | CCO mode(s) | What the pod receives |
|----------|-------------|-----------------------|
| **Static credentials** | `mint`, `passthrough`, `default` | A secret with `aws_access_key_id` / `aws_secret_access_key`. |
| **Token authentication** | `manual` (STS / Web Identity) | A projected ServiceAccount token, a role ARN, and a mounted AWS credentials file. **No** static access/secret keys. |

In both cases the AWS credentials are consumed only to *sign* the RDS IAM token; the
database itself never sees an AWS key.

## Background: how RDS IAM authentication works

An RDS IAM authentication token is a **SigV4-presigned request** to the `rds-db` service:

```
GET https://{host}:{port}/?Action=connect&DBUser={username}
```

signed with the AWS credentials and the DB region, with the signature carried in the query
string (`X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Expires`, ...). The scheme
(`https://`) is stripped, and the resulting string is passed to PostgreSQL **as the
connection password**. The database user must have been granted `rds_iam` (e.g.
`GRANT rds_iam TO trustify_user;`), and TLS is mandatory.

Key property: the token is valid for **15 minutes** ([`RDS_IAM_TOKEN_EXPIRY`]). It only
needs to be valid at the moment a *new* physical connection authenticates — connections
that are already established keep working after the token that opened them expires.

## Configuration

Two configuration options gate and parameterise IAM authentication (see
`common/src/config.rs`, struct `Database`):

| CLI flag | Env var | Meaning |
|----------|---------|---------|
| `--db-iam-auth` | `TRUSTD_DB_IAM_AUTH` | Enable RDS IAM authentication (default `false`). |
| `--db-region` | `TRUSTD_DB_REGION` | AWS region of the RDS/Aurora instance. **Required** when `iam_auth` is enabled. |

Both conflict with `--db-url` (`TRUSTD_DB_URL`): IAM authentication builds the connection
from the individual host/port/user/name fields and injects the generated token as the
password, so a pre-built DSN is not supported. The static `--db-password`
(`TRUSTD_DB_PASSWORD`) is ignored when IAM auth is enabled.

The read-only database config (`DatabaseReadOnly`) inherits `iam_auth` and `region` from
the read-write config: a read replica reached with IAM auth uses the same mechanism and
region.

The kubernetes operator sets `TRUSTD_DB_IAM_AUTH=true` and `TRUSTD_DB_REGION` (and omits the DB
password) when `ccoRds.enabled` is configured, alongside the same AWS credential wiring
used for S3 in `manual` mode.

## Implementation

### Token generation — `common/src/db/rds_iam.rs`

`generate_rds_iam_token(host, port, username, region)` produces the token:

1. Loads the AWS default credential provider chain
   (`aws_config::defaults(BehaviorVersion::latest())`) pinned to the DB region, and
   resolves credentials from it. On OpenShift this resolves to the CCO-provisioned
   credentials — static keys, or the Web Identity/STS token in `manual` mode — so **no
   static AWS keys are required**.
2. Uses `aws-sigv4` to presign a `GET` request to the `rds-db` service with
   `SignatureLocation::QueryParams` and `expires_in = RDS_IAM_TOKEN_EXPIRY`. The URL is
   built with the `url` crate's query-string API so the `DBUser` value (the database
   username) is properly percent-encoded — interpolating it directly would let characters
   such as `&`, `=` or spaces corrupt the query and yield a token for the wrong user or a
   rejected one.
3. Applies the signing query parameters to the URL and strips the `https://` prefix,
   yielding exactly the format the AWS SDKs' `generate_db_auth_token` helpers produce.

The credentials are resolved fresh on every call, so a refreshed STS token is always
picked up. Credential resolution is split from the (synchronous) signing in a private
`presign_rds_iam_token(host, port, username, region, credentials, time)` helper, so the
signing can be unit-tested with injected credentials — no AWS calls, no environment
mutation.

### Self-refreshing connection pool — `common/src/db/mod.rs`

`Database::new` branches to `Database::new_with_iam_auth` when `iam_auth` is set. Before
opening the pool it validates that IAM auth can actually work: `--db-region` must be set,
and the AWS credential environment must be configured (checked cheaply via
`trustify_common::aws::aws_credentials_configured`). If no AWS credential source is present
it fails fast with a clear error rather than attempting an AWS-authenticated connection
that cannot succeed. Because a
connection pool opens new physical connections over its lifetime but a token lives only
15 minutes, a single token captured at startup would eventually fail new connections. The
challenge: `sqlx` has **no per-connection password callback** — the password lives in the
`PgConnectOptions` used to open a connection.

The mechanism that makes self-refreshing work is
[`sqlx::Pool::set_connect_options`], which swaps the `PgConnectOptions` used for **new**
connections (existing connections are unaffected). So:

1. An initial token is generated and used to build `PgConnectOptions` (host/port/user/name
   + token as password + TLS-forced SSL mode). The pool is created with `sqlx`'s
   `PgPoolOptions` (honouring the same max/min-conn and timeout settings as the static
   path), then wrapped into a SeaORM connection via
   `SqlxPostgresConnector::from_sqlx_postgres_pool`.
2. `spawn_iam_token_refresher` starts a background `tokio` task that, every
   [`RDS_IAM_TOKEN_REFRESH`] (10 minutes — comfortably below the 15-minute expiry),
   regenerates the token and calls `set_connect_options` with it. New connections then
   authenticate with the fresh token. The task exits when the pool is closed; a failed
   refresh is logged and retried on the next tick (the current, not-yet-expired token and
   all open connections remain usable in the meantime).

### TLS is forced

RDS IAM authentication mandates TLS. `require_tls` promotes any SSL mode weaker than
`Require` (`Disable`, `Allow`, `Prefer`) up to `Require`, while leaving stricter modes
(`VerifyCa`, `VerifyFull`) untouched. This guarantees the token is never sent over an
unencrypted connection even if the deployment left the SSL mode at its default.

### RDS/Aurora IAM database authentication

When `TRUSTD_DB_IAM_AUTH=true`, the database password is replaced by a short-lived AWS RDS
IAM authentication token:

* `TRUSTD_DB_REGION` is **required**; `TRUSTD_DB_URL` must not be set, and
  `TRUSTD_DB_PASSWORD` is ignored.
* The token is generated from the AWS default credential provider chain (the same chain,
  including the Web Identity/STS provider, used for S3), and refreshed automatically before
  its ~15-minute expiry for new pooled connections.
* TLS is forced to at least `require` (RDS IAM authentication mandates TLS), so a weaker
  `TRUSTD_DB_SSLMODE` is promoted to `require`.

This enables **token authentication** for the database via OpenShift's Cloud Credential
Operator (`ccoRds`). See
[docs/design/rds-iam-cco-token-authentication.md](design/rds-iam-cco-token-authentication.md).

## Configuration summary

| `TRUSTD_DB_IAM_AUTH` | Credential / password source |
|----------------------|------------------------------|
| unset / `false` | Static `TRUSTD_DB_PASSWORD` (or `TRUSTD_DB_URL`) — unchanged behaviour. |
| `true` | RDS IAM token generated from the AWS default credential provider chain (env / profile / **web-identity (STS)** / IMDS), refreshed automatically. `TRUSTD_DB_REGION` required; TLS forced to at least `require`. |

The web-identity path relies on the standard AWS SDK environment variables
(`AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_SHARED_CREDENTIALS_FILE`), which the
kubernetes operator sets automatically in `manual` mode. When running outside the operator, set
those variables (or provide static AWS keys) yourself to use token authentication.

## Testing

* `common/src/db/rds_iam.rs` — `token_has_expected_shape` presigns a token against fixed
  AWS documentation example credentials (injected directly into `presign_rds_iam_token`, so
  the test neither contacts AWS nor mutates process-wide environment variables) and asserts
  its shape: `host:port/?Action=connect&DBUser=...` plus the SigV4 query parameters
  (`X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Expires`), with the scheme stripped.
* `username_is_url_encoded` presigns with a username containing `&`, `=` and a space, and
  asserts it is percent-encoded into a single, uncorrupted `DBUser` parameter.
* End-to-end validation of the actual IAM handshake requires a real RDS/Aurora instance
  with an `rds_iam`-granted role (or an OpenShift cluster with CCO) and is out of scope for
  the unit tests.

[`RDS_IAM_TOKEN_EXPIRY`]: ../../common/src/db/rds_iam.rs
[`RDS_IAM_TOKEN_REFRESH`]: ../../common/src/db/rds_iam.rs
[`sqlx::Pool::set_connect_options`]: https://docs.rs/sqlx/latest/sqlx/struct.Pool.html#method.set_connect_options

### RDS/Aurora IAM database authentication

When `TRUSTD_DB_IAM_AUTH=true`, the database password is replaced by a short-lived AWS RDS
IAM authentication token:

* `TRUSTD_DB_REGION` is **required**; `TRUSTD_DB_URL` must not be set, and
  `TRUSTD_DB_PASSWORD` is ignored.
* The token is generated from the AWS default credential provider chain (the same chain,
  including the Web Identity/STS provider, used for S3), and refreshed automatically before
  its ~15-minute expiry for new pooled connections.
* TLS is forced to at least `require` (RDS IAM authentication mandates TLS), so a weaker
  `TRUSTD_DB_SSLMODE` is promoted to `require`.

This enables **token authentication** for the database via OpenShift's Cloud Credential
Operator (`ccoRds`). See
[docs/design/rds-iam-cco-token-authentication.md](design/rds-iam-cco-token-authentication.md).
