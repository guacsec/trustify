# ENVIRONMENT VARIABLES

| Environment Variable                     | Description                                                                         | Default Value                           |
|------------------------------------------|-------------------------------------------------------------------------------------|-----------------------------------------|
| `AUTHENTICATION_DISABLED`                | Disable authentication                                                              | `false`                                 |
| `AUTHENTICATOR_OIDC_CLIENT_IDS`          | Set allowed client IDs (comma separated)                                            |                                         |
| `AUTHENTICATOR_OIDC_ISSUER_URL`          | Issuer URL of the clients                                                           |                                         |
| `AUTHENTICATOR_OIDC_REQUIRED_AUDIENCE`   | Enforce an "audience" to be present in the access token                             |                                         |
| `AUTHENTICATOR_OIDC_TLS_CA_CERTIFICATES` | Enable additional TLS certificates for communication with the SSO server            |                                         |
| `AUTHENTICATOR_OIDC_TLS_INSECURE`        | Allow insecure TLS connections with the SSO server                                  |                                         |
| `AUTH_CONFIGURATION`                     | Location of the AuthNZ configuration file                                           |                                         |
| `AUTH_DISABLED`                          | Disable authentication and authorization                                            | `false`                                 |
| `CLIENT_TLS_CA_CERTIFICATES`             | Additional certificates which will be added as trust anchors                        |                                         |
| `CLIENT_TLS_INSECURE`                    | Make the TLS client insecure, disabling all validation                              | `false`                                 |
| `HTTP_SERVER_BIND_ADDR`                  | Address to listen on                                                                | `::1`                                   |
| `HTTP_SERVER_DISABLE_LOG`                | Disable the request log                                                             | `false`                                 |
| `HTTP_SERVER_JSON_LIMIT`                 | JSON request limit                                                                  | `2 MiB`                                 |
| `HTTP_SERVER_REQUEST_LIMIT`              | Overall request limit                                                               | `256 KiB`                               |
| `HTTP_SERVER_TLS_CERTIFICATE_FILE`       | Path to the TLS certificate in PEM format                                           |                                         |
| `HTTP_SERVER_TLS_ENABLED`                | Enable TLS                                                                          | `false`                                 |
| `HTTP_SERVER_TLS_KEY_FILE`               | Path to the TLS key file in PEM format                                              |                                         |
| `HTTP_SERVER_WORKERS`                    | Number of worker threads, defaults to zero, which falls back to the number of cores | `0`                                     |
| `IMPORTER_CONCURRENCY`                   | The maximum number of jobs run simultaneously by the importer                       | `1`                                     |
| `IMPORTER_WORKING_DIR`                   | Where the importer downloads documents prior to ingesting them                      | `tempdir`                               |
| `OIDC_PROVIDER_CLIENT_ID`                | OIDC client ID used for retrieving access tokens                                    |                                         |
| `OIDC_PROVIDER_CLIENT_SECRET`            | Secret matching the OIDC client ID                                                  |                                         |
| `OIDC_PROVIDER_ISSUER_URL`               | OIDC issuer to request access tokens from                                           |                                         |
| `OIDC_PROVIDER_REFRESH_BEFORE`           | Duration an access token must still be valid before requesting a new one            | `30s`                                   |
| `OIDC_PROVIDER_TLS_INSECURE`             | Insecure TLS when contacting the OIDC issuer                                        | `false`                                 |
| `OPENAI_API_KEY`                         | OpenAI access key                                                                   |                                         |
| `OPENAI_API_BASE`                        | To set the base URL path for API requests                                           | `https://api.openapi.com/v1`            |
| `OPENAI_MODEL`                           | OpenAI model                                                                        | `gpt-4o`                                |
| `TRUSTD_DB_HOST`                         | Database address                                                                    | `localhost`                             |
| `TRUSTD_DB_MAX_CONN`                     | Database max connections                                                            | `75`                                    |
| `TRUSTD_DB_MIN_CONN`                     | Database min connections                                                            | `25`                                    |
| `TRUSTD_DB_CONNECT_TIMEOUT`              | Database connect timeout (humantime)                                                | `8s`                                    |
| `TRUSTD_DB_ACQUIRE_TIMEOUT`              | Database acquire timeout (humantime)                                                | `8s`                                    |
| `TRUSTD_DB_MAX_LIFETIME`                 | Database max lifetime (humantime)                                                   | `7200s`                                 |
| `TRUSTD_DB_IDLE_TIMEOUT`                 | Database idle timeout (humantime)                                                   | `600s`                                  |
| `TRUSTD_DB_NAME`                         | Database name                                                                       | `trustify`                              |
| `TRUSTD_DB_PASSWORD`                     | Database password                                                                   | `trustify`                              |
| `TRUSTD_DB_PORT`                         | Database port                                                                       | `5432`                                  |
| `TRUSTD_DB_USER`                         | Database username                                                                   | `postgres`                              |
| `TRUSTD_GC_FREQ`                         | How often database garbage collection runs (humantime)                              | `5m`                                    |
| `TRUSTD_ISSUER_URL`                      | Issuer URL for `--devmode`                                                          | `http://localhost:8090/realms/trustify` |
| `TRUSTD_MAX_CACHE_SIZE`                  | Maximum size of the graph cache.                                                    | `200 MiB`                               |
| `TRUSTD_S3_ACCESS_KEY`                   | S3 access key                                                                       |                                         |
| `TRUSTD_S3_BUCKET`                       | S3 bucket name                                                                      |                                         |
| `TRUSTD_S3_REGION`                       | S3 region name                                                                      |                                         |
| `TRUSTD_S3_SECRET_KEY`                   | S3 secret key                                                                       |                                         |
| `TRUSTD_STORAGE_FS_PATH`                 | Path for storage file system strategy                                               | `./.trustify/storage`                   |
| `TRUSTD_STORAGE_STRATEGY`                | Specifies the storage strategy to use                                               | `File system`                           |
| `TRUSTD_WITH_GRAPHQL`                    | Allows enabling the GraphQL endpoint                                                | `false`                                 |
| `UI_CLIENT_ID`                           | Client ID used by the UI                                                            | `frontend`                              |
| `UI_ISSUER_URL`                          | Issuer URL used by the UI                                                           | `http://localhost:8090/realms/trustify` |
| `UI_SCOPE`                               | Scopes to request                                                                   | `openid`                                |

## Development 

| Environment Variable         | Description                                                                                                 | Default Value |
|------------------------------|-------------------------------------------------------------------------------------------------------------|---------------|
| `EXTERNAL_TEST_DB`           | Run tests against external test database if set                                                             |               |
| `EXTERNAL_TEST_DB_BOOTSTRAP` | Run tests against external test database if set                                                             |               |
| `MEM_LIMIT_MB`               | Set memory limit for tests that use TrustifyContext, shows the memory usage when the test reaches the limit | `500 MiB`     |
