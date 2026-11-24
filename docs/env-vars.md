# ENVIRONMENT VARIABLES

Settings apply only to commands that consume them. Where a corresponding CLI
option exists, it overrides the environment variable. A blank default means unset
or empty unless the description says otherwise.

`AUTHENTICATION_DISABLED`, `CLIENT_TLS_*`, and `OIDC_PROVIDER_*` exist as library
argument definitions but are not wired into the current executables. Use
`AUTH_DISABLED` for API authentication and the service-specific TLS/OIDC settings
below. The executables do not read `OPENAI_API_KEY`, `OPENAI_API_BASE`, or
`OPENAI_MODEL`.

| Environment Variable                     | Description                                                                         | Default Value                           |
|------------------------------------------|-------------------------------------------------------------------------------------|-----------------------------------------|
| `AUTHENTICATOR_OIDC_CLIENT_IDS`          | Set allowed client IDs (comma separated)                                            |                                         |
| `AUTHENTICATOR_OIDC_ISSUER_URL`          | Issuer URL of the clients                                                           |                                         |
| `AUTHENTICATOR_OIDC_REQUIRED_AUDIENCE` | Require the configured audience value in the access token’s `aud` claim |  |
| `AUTHENTICATOR_OIDC_TLS_CA_CERTIFICATES` | Enable additional TLS certificates for communication with the SSO server            |                                         |
| `AUTHENTICATOR_OIDC_TLS_INSECURE` | Allow insecure TLS connections with the SSO server | `false` |
| `AUTH_CONFIGURATION`                     | Location of the AuthNZ configuration file                                           |                                         |
| `AUTH_DISABLED`                          | Disable authentication and authorization                                            | `false`                                 |
| `HTTP_SERVER_BIND_ADDR`                  | Address to listen on                                                                | `::1`                                   |
| `HTTP_SERVER_CORS_ALLOWED_ORIGINS`       | Comma-separated list of origins allowed for cross-origin requests; empty means same-origin only |                                         |
| `HTTP_SERVER_CORS_PERMISSIVE`            | Allow any CORS origin, method, and header; development only and unsafe for production | `false`                                 |
| `HTTP_SERVER_DISABLE_LOG`                | Disable the request log                                                             | `false`                                 |
| `HTTP_SERVER_JSON_LIMIT`                 | JSON request limit                                                                  | `2 MiB`                                 |
| `HTTP_SERVER_REQUEST_LIMIT`              | Overall request limit                                                               | `256 KiB`                               |
| `HTTP_SERVER_SECURITY_HEADERS_DISABLED`  | Disable the default security response headers; disabling weakens defense-in-depth protections | `false`                                 |
| `HTTP_SERVER_CSP`                        | Content-Security-Policy header value; empty omits CSP                              | `frame-ancestors 'none'`               |
| `HTTP_SERVER_HSTS`                       | Strict-Transport-Security value; opt-in, only applied when TLS is enabled, and honored over HTTPS |                                         |
| `HTTP_SERVER_TLS_CERTIFICATE_FILE`       | Path to the TLS certificate in PEM format                                           |                                         |
| `HTTP_SERVER_TLS_CIPHERS`                | TLS 1.2 cipher list in OpenSSL format (custom profile only)                         |                                         |
| `HTTP_SERVER_TLS_CIPHERSUITES`           | TLS 1.3 ciphersuites in OpenSSL format (custom profile only)                        |                                         |
| `HTTP_SERVER_TLS_ENABLED`                | Enable TLS                                                                          | `false`                                 |
| `HTTP_SERVER_TLS_GROUPS`                 | Key-exchange groups in OpenSSL format, preference order, `:` separated (all profiles) |                                       |
| `HTTP_SERVER_TLS_KEY_FILE`               | Path to the TLS key file in PEM format                                              |                                         |
| `HTTP_SERVER_TLS_MIN_VERSION`            | Minimum TLS version for custom profile: 1.0, 1.1, 1.2, 1.3                         |                                         |
| `HTTP_SERVER_TLS_SECURITY_PROFILE`       | TLS security profile: old, intermediate, modern, custom                             | `modern`                                |
| `HTTP_SERVER_WORKERS` | Actix HTTP request worker threads per API server; `0` uses Actix’s default based on available CPU parallelism | `0` |
| `IMPORTER_CONCURRENCY` | Maximum concurrent importer runs per importer process; `0` uses available CPU parallelism | `1` |
| `IMPORTER_CREDENTIAL_PATHS`              | Comma-separated list of allowed base paths for file credential sources; empty = deny all file credentials | |
| `IMPORTER_ENV_PREFIXES`                  | Comma-separated list of required prefixes for env var credential sources; empty = deny all env var credentials | |
| `IMPORTER_WORKING_DIR`                   | Where the importer downloads documents prior to ingesting them                      | `tempdir`                               |
| `TRUSTD_CORRELATION_WORKERS` | Concurrent background correlation tasks per API or worker process; `0` uses available CPU parallelism | `1` |
| `TRUSTD_CORRELATION_MATCH_BATCH` | Target number of buffered SBOM matches per correlation task before writing evidence; must be > 0; a single node can exceed it | `100000` |
| `TRUSTD_CORRELATION_WORK_MEM` | Transaction-local PostgreSQL `work_mem` for correlation tasks (e.g. `256MiB`); unset uses the database setting; not a total worker memory limit |  |
| `TRUSTD_AWS_USE_IMDS` | Opt into the AWS default credential chain for IMDS-only credentials (e.g. EC2); only the exact value `true` enables this |  |
| `TRUSTD_CHANGE_LOG_RETENTION`            | Retention of the change log entries, which notify clients and wake up workers (humantime)| `1d`                                    |
| `TRUSTD_CHANGE_LOG_POLL_INTERVAL`        | Interval of the change log fallback sweep (humantime)                               | `30s`                                   |
| `TRUSTD_CHANGE_LOG_CLEANUP_INTERVAL`     | Interval of removing expired change log entries (humantime)                         | `5m`                                    |
| `TRUSTD_DEVMODE_ADDITIONAL_CLIENTS`      | Additional allowed development OAuth clients                                        |                                         |
| `TRUSTD_DISABLE_CORRELATION` | Disable the correlation API capability and in-process correlation tasks in `trustd api`; does not stop separate worker processes | `false` |
| `TRUSTD_DISABLE_CORRELATION_WORKER` | Disable only the in-process correlation tasks in `trustd api`, keeping the correlation API available for use with `trustd worker` | `false` |
| `TRUSTD_DISABLE_FORMATS`                 | Disable these document formats (comma-separated); use `*` to disable all            |                                         |
| `TRUSTD_DISABLE_IMPORTERS`               | Disable these importer types (comma-separated); use `*` to disable all              |                                         |
| `TRUSTD_ENABLE_FORMATS`                  | Enable only these document formats (comma-separated); conflicts with `TRUSTD_DISABLE_FORMATS` |                                |
| `TRUSTD_ENABLE_IMPORTERS`                | Enable only these importer types (comma-separated); conflicts with `TRUSTD_DISABLE_IMPORTERS` |                                |
| `TRUSTD_DB_URL`                          | Complete database URL; conflicts with the other `TRUSTD_DB_*` connection settings   |                                         |
| `TRUSTD_DB_HOST`                         | Database address                                                                    | `localhost`                             |
| `TRUSTD_DB_MAX_CONN`                     | Database max connections                                                            | `75`                                    |
| `TRUSTD_DB_MIN_CONN`                     | Database min connections                                                            | `25`                                    |
| `TRUSTD_DB_CONNECT_TIMEOUT`              | Database connect timeout (humantime, or seconds)                                    | `8s`                                    |
| `TRUSTD_DB_ACQUIRE_TIMEOUT`              | Database acquire timeout (humantime, or seconds)                                    | `8s`                                    |
| `TRUSTD_DB_MAX_LIFETIME`                 | Database max lifetime (humantime, or seconds)                                       | `2h`                                    |
| `TRUSTD_DB_IDLE_TIMEOUT`                 | Database idle timeout (humantime, or seconds)                                       | `10m`                                   |
| `TRUSTD_DB_NAME`                         | Database name                                                                       | `trustify`                              |
| `TRUSTD_DB_PASSWORD`                     | Database password (ignored when IAM authentication is enabled)                      | `trustify`                              |
| `TRUSTD_DB_PORT`                         | Database port                                                                       | `5432`                                  |
| `TRUSTD_DB_USER`                         | Database username                                                                   | `postgres`                              |
| `TRUSTD_DB_SSLMODE`                      | Database SSL mode: disable, allow, prefer, require, verify-ca, verify-full          | `prefer`                                |
| `TRUSTD_DB_IAM_AUTH`                     | Authenticate with an AWS RDS/Aurora IAM token instead of a password                 | `false`                                 |
| `TRUSTD_DB_IAM_REGION`                   | AWS region of the RDS/Aurora instance (required when `TRUSTD_DB_IAM_AUTH=true`)     |                                         |
| `TRUSTD_DB_RO_URL`                       | Complete URL of the read-only database; falls back to `TRUSTD_DB_URL`               |                                         |
| `TRUSTD_DB_RO_HOST`                      | Address of the read-only database; falls back to `TRUSTD_DB_HOST`                   |                                         |
| `TRUSTD_DB_RO_PORT`                      | Port of the read-only database; falls back to `TRUSTD_DB_PORT`                      |                                         |
| `TRUSTD_DB_RO_NAME`                      | Name of the read-only database; falls back to `TRUSTD_DB_NAME`                      |                                         |
| `TRUSTD_DB_RO_USER`                      | Username of the read-only database; falls back to `TRUSTD_DB_USER`                  |                                         |
| `TRUSTD_DB_RO_PASSWORD`                  | Password of the read-only database; falls back to `TRUSTD_DB_PASSWORD`              |                                         |
| `TRUSTD_DB_RO_SSLMODE`                   | SSL mode of the read-only database; falls back to `TRUSTD_DB_SSLMODE`               |                                         |
| `TRUSTD_DB_RO_MAX_CONN`                  | Max connections of the read-only database; falls back to `TRUSTD_DB_MAX_CONN`       |                                         |
| `TRUSTD_DB_RO_MIN_CONN`                  | Min connections of the read-only database; falls back to `TRUSTD_DB_MIN_CONN`       |                                         |
| `TRUSTD_DB_RO_CONNECT_TIMEOUT`           | Connect timeout (humantime, or seconds) of the read-only database; falls back to `TRUSTD_DB_CONNECT_TIMEOUT`|                                         |
| `TRUSTD_DB_RO_ACQUIRE_TIMEOUT`           | Acquire timeout (humantime, or seconds) of the read-only database; falls back to `TRUSTD_DB_ACQUIRE_TIMEOUT`|                                         |
| `TRUSTD_DB_RO_MAX_LIFETIME`              | Max lifetime (humantime, or seconds) of the read-only database; falls back to `TRUSTD_DB_MAX_LIFETIME`|                                         |
| `TRUSTD_DB_RO_IDLE_TIMEOUT`              | Idle timeout (humantime, or seconds) of the read-only database; falls back to `TRUSTD_DB_IDLE_TIMEOUT`|                                         |
| `TRUSTD_PAGINATION_TOTAL_CACHE_TTL`      | TTL for cached pagination total counts (humantime)                                  | `60s`                                   |
| `TRUSTD_ISSUER_URL`                      | Issuer URL for `--devmode`                                                          | `http://localhost:8090/realms/trustify` |
| `TRUSTD_MAX_CACHE_SIZE`                  | Maximum size of the graph cache.                                                    | `200 MiB`                               |
| `TRUSTIFY_LATEST_SBOM_PUBLISHED_CUTOFF_DAYS` | Number of days before now used as a published-date cutoff when finding latest SBOMs [disabled by default] |                                         |
| `TRUSTD_READ_ONLY` | Reject mutating API requests and suppress in-process correlation/EI tasks in `trustd api`; suspend importer runs in `trustd importer`; does not affect `trustd worker` | `false` |
| `TRUSTD_SBOM_UPLOAD_LIMIT`               | Size limit of SBOMs, uncompressed                                                   | `1 GiB`                                 |
| `TRUSTD_ADVISORY_UPLOAD_LIMIT`           | Size limit of advisories, uncompressed                                              | `128 MiB`                               |
| `TRUSTD_DATASET_ENTRY_LIMIT`             | Size limit of documents in a dataset, uncompressed                                  | `1 GiB`                                 |
| `TRUSTD_SCAN_LIMIT`                      | Size limit of documents for a scan, uncompressed                                    | `1 GiB`                                 |
| `TRUSTD_MAX_GROUP_NAME_LENGTH`           | Maximum length of a group name                                                      | `255`                                   |
| `TRUSTD_RECOMMEND_REPORT_PACKAGE_LIMIT`  | Maximum number of packages (across all SBOMs) of one recommendation report request  | `10000`                                 |
| `TRUSTD_PAGINATION_MAX_LIMIT`            | Maximum limit of pagination queries (`0` = no maximum)                              | `1000`                                  |
| `TRUSTIFY_ANALYSIS_CONCURRENCY` | Concurrent graph loading and collection operations within analysis requests; must be > 0 | `10` |
| `TRUSTD_WORKER_JOBS` | Job types for `trustd worker` (comma-separated); currently only `correlation`; does not set the task count | `correlation` |
| `TRUSTD_RECOMMEND_PATTERNS`              | Comma-separated list of regex patterns, each with exactly one capture group that extracts the upstream base version. Example: `^(.+)[.-]redhat-[0-9]+$,^(.+)[.-]rhlw-[0-9]+$`. Absent or empty causes endpoints to return HTTP 422 with `CapabilityDisabled`. | (empty) |
| `TRUSTD_S3_ACCESS_KEY`                   | S3 access key                                                                       |                                         |
| `TRUSTD_S3_BUCKET`                       | S3 bucket name                                                                      |                                         |
| `TRUSTD_S3_REGION`                       | S3 region name                                                                      |                                         |
| `TRUSTD_S3_SECRET_KEY`                   | S3 secret key                                                                       |                                         |
| `TRUSTD_S3_TRUST_ANCHORS` | Comma-separated paths to additional PEM trust anchors for S3 connections | |
| `TRUSTD_S3_PATH_STYLE` | Use S3 path-style addressing instead of virtual-host style | `false` |
| `TRUSTD_SLOW_SQL_THRESHOLD`              | Override threshold for slow SQL statements (humantime)                              | `1m`                                    |
| `TRUSTD_STORAGE_COMPRESSION`             | Compression of stored documents: none, zstd                                         | `none`                                  |
| `TRUSTD_STORAGE_FS_PATH`                 | Path for storage file system strategy                                               | `./.trustify/storage`                   |
| `TRUSTD_STORAGE_STRATEGY` | Storage backend: `fs` (file system) or `s3` | `fs` |
| `TRUSTD_VALIDATORS_CONFIG`               | Path to a semantic validators configuration file (YAML); unset disables validation  |                                         |
| `SWAGGER_UI_OIDC_ISSUER_URL` | OIDC issuer used for Swagger UI discovery; unset disables Swagger UI OIDC outside development mode | |
| `SWAGGER_UI_OIDC_CLIENT_ID` | Client ID used by Swagger UI | `frontend` |
| `SWAGGER_UI_OIDC_TLS_INSECURE` | Disable TLS verification for Swagger UI OIDC discovery | `false` |
| `SWAGGER_UI_OIDC_TLS_CA_CERTIFICATES` | Additional certificate paths trusted for Swagger UI OIDC discovery | |
| `UI_CLIENT_ID`                           | Client ID used by the UI                                                            | `frontend`                              |
| `UI_ISSUER_URL`                          | Issuer URL used by the UI                                                           | `http://localhost:8090/realms/trustify` |
| `UI_LOAD_USER`                           | Whether to load user info                                                           | `true`                                  |
| `UI_SCOPE`                               | Scopes to request                                                                   | `openid`                                |
| `EXPLOIT_INTELLIGENCE_URL`               | Base URL of the Exploit Intelligence client service                                 |                                         |
| `EXPLOIT_INTELLIGENCE_UI_URL`            | Base URL of the EI web UI for deep-linking to reports (falls back to `EXPLOIT_INTELLIGENCE_URL` if unset) |                   |
| `EXPLOIT_INTELLIGENCE_MAX_RETRIES`       | Maximum number of retry attempts before marking a job as permanently failed         | `3`                                     |
| `EXPLOIT_INTELLIGENCE_WORKER_POLL_INTERVAL` | Interval between each EI loop’s job checks and minimum interval before re-polling a running job (humantime) | `5s` |
| `EXPLOIT_INTELLIGENCE_CONCURRENCY` | Concurrent EI job-processing loops per API process; `0` starts no loops; requires `EXPLOIT_INTELLIGENCE_URL` and read-write mode | `5` |
| `EXPLOIT_INTELLIGENCE_AUTH_TOKEN`        | Static authentication token for the EI service (for backward compatibility)         |                                         |
| `EXPLOIT_INTELLIGENCE_OIDC_ISSUER_URL`   | OIDC issuer URL for EI service authentication (client credentials flow with discovery) |                                      |
| `EXPLOIT_INTELLIGENCE_OIDC_CLIENT_ID`    | OIDC client ID for EI service authentication                                        |                                         |
| `EXPLOIT_INTELLIGENCE_OIDC_CLIENT_SECRET`| OIDC client secret for EI service authentication                                    |                                         |
| `EXPLOIT_INTELLIGENCE_OIDC_REFRESH_BEFORE`| Duration an EI access token must still be valid before requesting a new one        | `30s`                                   |
| `EXPLOIT_INTELLIGENCE_OIDC_TLS_INSECURE` | Allow insecure TLS connections with the EI OIDC issuer                              | `false`                                 |
| `EXPLOIT_INTELLIGENCE_OIDC_SCOPE`        | OAuth scope(s) of the EI token request, space-separated; unset sends no scope       |                                         |

## Concurrency and background workers

These controls apply to different work and are independent:

| Environment variable | CLI option | Command | Default | Meaning of `0` |
|----------------------|------------|---------|---------|----------------|
| `HTTP_SERVER_WORKERS` | `--http-server-workers` | `trustd api` | `0` | Use Actix’s default HTTP thread count based on available CPU parallelism |
| `IMPORTER_CONCURRENCY` | `--concurrency` | `trustd importer` | `1` | One concurrent importer run per available CPU |
| `TRUSTD_CORRELATION_WORKERS` | `--correlation-workers` | `trustd api`, `trustd worker` | `1` | One background correlation task per available CPU |
| `TRUSTIFY_ANALYSIS_CONCURRENCY` | `--concurrency` | `trustd api` | `10` | Invalid; must be greater than zero |
| `EXPLOIT_INTELLIGENCE_CONCURRENCY` | `--exploit-intelligence-concurrency` | `trustd api` | `5` | No EI processing loops |
| `MIGRATION_DATA_CONCURRENT` | `--concurrent` | Data migration options | `0` | One concurrent document per available CPU (falls back to `1` if detection fails) |

The importer limit counts importer runs, not individual document downloads or
HTTP request threads. Analysis concurrency bounds asynchronous operations within
analysis requests; it is not a server-wide request limit.

Each correlation task claims distinct work from the shared database and takes turns
extracting evidence, refreshing outdated documents, and computing SBOM verdicts.
`TRUSTD_CORRELATION_WORKERS` counts asynchronous tasks per process, not dedicated
threads, workers per job type, or workers per HTTP thread. Multiple API and worker
processes add their task counts together.

By default, `trustd api` runs correlation tasks once per API process. To move that
work to a separate process, set `TRUSTD_DISABLE_CORRELATION_WORKER=true` on the API
and run `trustd worker --job correlation --correlation-workers N`. The API retains
the correlation capability. `TRUSTD_WORKER_JOBS` maps to `--job` and selects job
types; it does not control concurrency or include the importer or EI processing.

`TRUSTD_DISABLE_CORRELATION=true` disables the API capability as well as its local
correlation tasks. `TRUSTD_READ_ONLY=true` suppresses local correlation and EI
tasks in the API and importer runs in the importer process. Neither setting stops
a separately running `trustd worker` process.

`TRUSTD_CORRELATION_MATCH_BATCH` is a buffering target per task, not a concurrency
setting or a strict memory cap: all matches for one node are written together.
`TRUSTD_CORRELATION_WORK_MEM` applies PostgreSQL `work_mem` only for the duration
of correlation transactions and does not cap the total memory used by a task or
process.

## TLS key-exchange groups

`HTTP_SERVER_TLS_GROUPS` sets the key-exchange groups the HTTPS listener
offers, most preferred first, in OpenSSL's `:`-separated syntax:

```
HTTP_SERVER_TLS_GROUPS=X25519MLKEM768:X25519:secp256r1
```

It differs from the other TLS settings in three ways worth knowing.

**It applies to every profile.** `HTTP_SERVER_TLS_CIPHERS` and
`HTTP_SERVER_TLS_CIPHERSUITES` are only read for the `custom` profile, but
groups are independent of the cipher suites, so this is honored whatever
`HTTP_SERVER_TLS_SECURITY_PROFILE` is set to.

**It is how post-quantum key exchange is configured.** Hybrid PQC in TLS 1.3 is
delivered through the key-exchange *group* `X25519MLKEM768` (X25519 +
ML-KEM-768, NIST FIPS 203), not through a cipher suite — the cipher suites are
unchanged. It requires TLS 1.3 and OpenSSL 3.5 or later. Note that
`X25519MLKEM768` is not FIPS-approved and must be left out of the list on a
server running in FIPS mode.

**Always keep a classical group in the list unless the listener is TLS 1.3
only.** The hybrid groups exist only in TLS 1.3. A list like

```
HTTP_SERVER_TLS_GROUPS=X25519MLKEM768
```

leaves a TLS 1.2 client that insists on ECDHE with no group in common, and its
handshake fails with "handshake failure" — while TLS 1.3 keeps working, which
makes it easy to miss. On the `old` and `intermediate` profiles, and on any
`custom` profile whose minimum is below 1.3, pair the hybrid group with
`X25519` or `secp256r1`:

```
HTTP_SERVER_TLS_GROUPS=X25519MLKEM768:X25519:secp256r1
```

Clients that support the hybrid group still get it; the classical entries are
only reached by those that cannot. With `modern`, or any profile pinned to
TLS 1.3, a PQC-only list is fine.

**Leaving it unset is a reasonable default.** The listener then uses the system
or OpenSSL default group list. On RHEL and Fedora — including the RHEL 10 based
container images — that is the *system* list: `crypto-policies` sets `Groups`
in `/etc/crypto-policies/back-ends/opensslcnf.config`, and the default policy
already offers `X25519MLKEM768` ahead of the classical groups. So an
unconfigured server on those images negotiates hybrid PQC and still serves
TLS 1.2 ECDHE clients. Set this when you need the choice pinned rather than
inherited from the host policy.

A value that is set but blank (empty or whitespace only) is treated as unset
rather than as an empty list, because an empty list is never what is meant and
OpenSSL accepts it silently: it would start the server and then fail every
TLS 1.3 handshake.

The names are passed through to OpenSSL unchanged, so any group the local
OpenSSL knows is accepted; the ones that appear in OpenShift's TLS profiles are
`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `X25519`,
`secp256r1`, `secp384r1` and `secp521r1`. OpenSSL rejects the whole list if it
contains a single name it does not recognise, and the server then fails to
start rather than silently falling back to a different key exchange — so a
typo, or a group newer than the OpenSSL in the image, is loud rather than
quiet.

Under the RHTPA operator this is normally not set by hand: enabling
`modules.tlsConfigurator.operandTls` makes the operator derive it from the
cluster-wide OpenShift TLS profile and publish it to the server.

## Data Migration

| Environment Variable           | Description                                                                                            | Default Value |
|--------------------------------|--------------------------------------------------------------------------------------------------------|---------------|
| `MIGRATION_DATA_CONCURRENT`    | Number of concurrent documents per migration runner; `0` uses available CPU parallelism (falls back to `1` if detection fails)          | `0`           |
| `MIGRATION_DATA_MAX_CONNECTIONS`| Maximum number of database connections for processing documents, zero falls back to the number of concurrent documents | `0` |
| `MIGRATION_DATA_CURRENT_RUNNER`| The instance number of the current runner (zero based)                                                 | `0`           |
| `MIGRATION_DATA_TOTAL_RUNNER`  | The total number of runners                                                                            | `1`           |
| `MIGRATION_DATA_SKIP_ALL`      | Skip running all data migrations (conflicts with `MIGRATION_DATA_SKIP`)                                | `false`       |
| `MIGRATION_DATA_SKIP`          | Skip the provided list of data migrations (conflicts with `MIGRATION_DATA_SKIP_ALL`)                   |               |

## Development 

| Environment Variable         | Description                                                                                                 | Default Value |
|------------------------------|-------------------------------------------------------------------------------------------------------------|---------------|
| `EXTERNAL_TEST_DB` | Use an external test database configured through `TRUSTD_DB_*` when set |  |
| `EXTERNAL_TEST_DB_BOOTSTRAP` | Bootstrap the external test database when `EXTERNAL_TEST_DB` is set and this is `1` or `true` |  |
| `MEM_LIMIT_MB` | Numeric peak-allocation threshold in MiB; teardown logs an error above it when run with `--test-threads=1` | `500` |
| `TRUST_TEST_BTRFS_DISABLE`   | Disable BTRFS snapshot support even if available                                                            |               |
| `TRUST_TEST_BTRFS_STORE` | Path to a BTRFS-backed directory for using snapshots for tests | Current directory |
