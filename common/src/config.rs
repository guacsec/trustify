use anyhow::anyhow;
use clap::ValueEnum;
use hide::Hide;
use humantime::parse_duration;
use std::env;
use time::ext::NumericalStdDuration;

const DB_NAME: &str = "trustify";
const DB_USER: &str = "postgres";
const DB_PASS: &str = "trustify";
const DB_HOST: &str = "localhost";
const DB_PORT: u16 = 5432;
const DB_MAX_CONN: u32 = 75;
const DB_MIN_CONN: u32 = 25;
const DB_CONNECT_TIMEOUT: u64 = 8;
const DB_ACQUIRE_TIMEOUT: u64 = 8;
const DB_MAX_LIFETIME: u64 = 7200;
const DB_IDLE_TIMEOUT: u64 = 600;

const ENV_DB_URL: &str = "TRUSTD_DB_URL";
const ENV_DB_NAME: &str = "TRUSTD_DB_NAME";
const ENV_DB_USER: &str = "TRUSTD_DB_USER";
const ENV_DB_PASS: &str = "TRUSTD_DB_PASSWORD";
const ENV_DB_HOST: &str = "TRUSTD_DB_HOST";
const ENV_DB_PORT: &str = "TRUSTD_DB_PORT";
const ENV_DB_MAX_CONN: &str = "TRUSTD_DB_MAX_CONN";
const ENV_DB_MIN_CONN: &str = "TRUSTD_DB_MIN_CONN";
const ENV_DB_CONNECT_TIMEOUT: &str = "TRUSTD_DB_CONNECT_TIMEOUT";
const ENV_DB_ACQUIRE_TIMEOUT: &str = "TRUSTD_DB_ACQUIRE_TIMEOUT";
const ENV_DB_MAX_LIFETIME: &str = "TRUSTD_DB_MAX_LIFETIME";
const ENV_DB_IDLE_TIMEOUT: &str = "TRUSTD_DB_IDLE_TIMEOUT";
const ENV_DB_SSLMODE: &str = "TRUSTD_DB_SSLMODE";
const ENV_DB_IAM_AUTH: &str = "TRUSTD_DB_IAM_AUTH";
const ENV_DB_REGION: &str = "TRUSTD_DB_REGION";

const ENV_DB_RO_URL: &str = "TRUSTD_DB_RO_URL";
const ENV_DB_RO_NAME: &str = "TRUSTD_DB_RO_NAME";
const ENV_DB_RO_USER: &str = "TRUSTD_DB_RO_USER";
const ENV_DB_RO_PASS: &str = "TRUSTD_DB_RO_PASSWORD";
const ENV_DB_RO_HOST: &str = "TRUSTD_DB_RO_HOST";
const ENV_DB_RO_PORT: &str = "TRUSTD_DB_RO_PORT";
const ENV_DB_RO_MAX_CONN: &str = "TRUSTD_DB_RO_MAX_CONN";
const ENV_DB_RO_MIN_CONN: &str = "TRUSTD_DB_RO_MIN_CONN";
const ENV_DB_RO_CONNECT_TIMEOUT: &str = "TRUSTD_DB_RO_CONNECT_TIMEOUT";
const ENV_DB_RO_ACQUIRE_TIMEOUT: &str = "TRUSTD_DB_RO_ACQUIRE_TIMEOUT";
const ENV_DB_RO_MAX_LIFETIME: &str = "TRUSTD_DB_RO_MAX_LIFETIME";
const ENV_DB_RO_IDLE_TIMEOUT: &str = "TRUSTD_DB_RO_IDLE_TIMEOUT";
const ENV_DB_RO_SSLMODE: &str = "TRUSTD_DB_RO_SSLMODE";

/// PostgreSQL SSL mode
#[derive(Copy, Clone, Debug, Default, clap::ValueEnum, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum SslMode {
    Disable,
    Allow,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

/// Database options
#[derive(clap::Parser, Debug, Clone, Eq, PartialEq)]
#[command(next_help_heading = "Database")]
#[group(id = "database")]
pub struct Database {
    /// A complete URL. Conflicts with the other database parameters.
    #[arg(id = "db-url", long, env = ENV_DB_URL)]
    pub url: Option<String>,
    #[arg(id = "db-user", long, env = ENV_DB_USER, default_value_t = DB_USER.into(), conflicts_with = "db-url")]
    pub username: String,
    #[arg(
        id = "db-password",
        long,
        env = ENV_DB_PASS,
        default_value = DB_PASS,
    )]
    pub password: Hide<String>,
    #[arg(id = "db-host", long, env = ENV_DB_HOST, default_value_t = DB_HOST.into(), conflicts_with = "db-url")]
    pub host: String,
    #[arg(id = "db-port", long, env = ENV_DB_PORT, default_value_t = DB_PORT.into(), conflicts_with = "db-url")]
    pub port: u16,
    #[arg(id = "db-name", long, env = ENV_DB_NAME, default_value_t = DB_NAME.into(), conflicts_with = "db-url")]
    pub name: String,
    #[arg(id = "db-max-conn", long, env = ENV_DB_MAX_CONN, default_value_t = DB_MAX_CONN.into(), conflicts_with = "db-url")]
    pub max_conn: u32,
    #[arg(id = "db-min-conn", long, env = ENV_DB_MIN_CONN, default_value_t = DB_MIN_CONN.into(), conflicts_with = "db-url")]
    pub min_conn: u32,
    #[arg(id="db-sslmode", long, env = ENV_DB_SSLMODE, default_value_t, conflicts_with = "db-url", value_enum)]
    pub sslmode: SslMode,

    /// Authenticate to the database with an AWS RDS/Aurora IAM token instead of a
    /// static password. When enabled, the password is generated (and periodically
    /// refreshed) from AWS credentials and `region`, and TLS is forced on (RDS IAM
    /// authentication mandates TLS). Set by the RHTPA operator when CCO-backed RDS IAM
    /// authentication (`ccoRds`) is enabled.
    #[arg(id="db-iam-auth", long, env = ENV_DB_IAM_AUTH, default_value_t = false, conflicts_with = "db-url")]
    pub iam_auth: bool,

    /// AWS region of the RDS/Aurora instance. Required when `iam_auth` is enabled.
    #[arg(id="db-region", long, env = ENV_DB_REGION, conflicts_with = "db-url", required_if_eq("db-iam-auth", "true"))]
    pub region: Option<String>,

    #[arg(id="db-conn-timeout", long, env = ENV_DB_CONNECT_TIMEOUT, default_value_t=DB_CONNECT_TIMEOUT.into(), conflicts_with = "db-url")]
    pub connect_timeout: u64,
    #[arg(id="db-acquire-timeout", long, env = ENV_DB_ACQUIRE_TIMEOUT, default_value_t=DB_ACQUIRE_TIMEOUT.into(), conflicts_with = "db-url")]
    pub acquire_timeout: u64,
    #[arg(id="db-max-lifetime", long, env = ENV_DB_MAX_LIFETIME, default_value_t=DB_MAX_LIFETIME.into(), conflicts_with = "db-url")]
    pub max_lifetime: u64,
    #[arg(id="db-idle-timeout", long, env = ENV_DB_IDLE_TIMEOUT, default_value_t=DB_IDLE_TIMEOUT.into(), conflicts_with = "db-url")]
    pub idle_timeout: u64,
}

impl Database {
    pub fn from_env() -> Result<Database, anyhow::Error> {
        Ok(Database {
            url: env::var(ENV_DB_URL).ok(),
            username: env::var(ENV_DB_USER).unwrap_or(DB_USER.into()),
            password: env::var(ENV_DB_PASS).unwrap_or(DB_PASS.into()).into(),
            name: env::var(ENV_DB_NAME).unwrap_or(DB_NAME.into()),
            host: env::var(ENV_DB_HOST).unwrap_or(DB_HOST.into()),
            port: match env::var(ENV_DB_PORT) {
                Ok(s) => s.parse::<u16>()?,
                _ => DB_PORT,
            },
            max_conn: match env::var(ENV_DB_MAX_CONN) {
                Ok(s) => s.parse::<u32>()?,
                _ => DB_MAX_CONN,
            },
            min_conn: match env::var(ENV_DB_MIN_CONN) {
                Ok(s) => s.parse::<u32>()?,
                _ => DB_MIN_CONN,
            },
            connect_timeout: match env::var(ENV_DB_CONNECT_TIMEOUT) {
                Ok(s) => parse_duration(&s)
                    .unwrap_or(DB_IDLE_TIMEOUT.std_seconds())
                    .as_secs(),
                _ => DB_CONNECT_TIMEOUT,
            },
            acquire_timeout: match env::var(ENV_DB_ACQUIRE_TIMEOUT) {
                Ok(s) => parse_duration(&s)
                    .unwrap_or(DB_ACQUIRE_TIMEOUT.std_seconds())
                    .as_secs(),
                _ => DB_ACQUIRE_TIMEOUT,
            },
            max_lifetime: match env::var(ENV_DB_MAX_LIFETIME) {
                Ok(s) => parse_duration(&s)
                    .unwrap_or(DB_MAX_LIFETIME.std_seconds())
                    .as_secs(),
                _ => DB_MAX_LIFETIME,
            },
            idle_timeout: match env::var(ENV_DB_IDLE_TIMEOUT) {
                Ok(s) => parse_duration(&s)
                    .unwrap_or(DB_IDLE_TIMEOUT.std_seconds())
                    .as_secs(),
                _ => DB_IDLE_TIMEOUT,
            },
            sslmode: match env::var(ENV_DB_SSLMODE) {
                Ok(s) => SslMode::from_str(&s, false)
                    .map_err(|s| anyhow!("Failed to convert '{s}' to SslMode"))?,
                _ => Default::default(),
            },
            iam_auth: match env::var(ENV_DB_IAM_AUTH) {
                Ok(s) => s.parse::<bool>().map_err(|_| {
                    anyhow!(
                        "Invalid boolean for {ENV_DB_IAM_AUTH}: '{s}' (expected 'true' or 'false')"
                    )
                })?,
                _ => false,
            },
            region: env::var(ENV_DB_REGION).ok(),
        })
    }

    pub fn to_url(&self) -> String {
        if let Some(url) = &self.url {
            return url.clone();
        }

        format!(
            "postgres://{username}:{password}@{host}:{port}/{db_name}?sslmode={sslmode}",
            username = self.username,
            password = self.password.0,
            host = self.host,
            port = self.port,
            db_name = self.name,
            sslmode = self.sslmode,
        )
    }

    pub fn from_port(port: u16) -> anyhow::Result<Self> {
        Ok(Self {
            username: "postgres".into(),
            password: "trustify".into(),
            host: "localhost".into(),
            name: "test".into(),
            port,
            ..Self::from_env()?
        })
    }
}

/// Read-only database options, mirroring `Database` with all fields optional.
///
/// When a field is not set, the corresponding value from the R/W `Database` config is used.
/// If no R/O fields are set at all, the R/W connection is reused for reads.
#[derive(clap::Parser, Debug, Clone, Default, Eq, PartialEq)]
#[command(next_help_heading = "Read-Only Database")]
#[group(id = "database-ro")]
pub struct DatabaseReadOnly {
    /// A complete URL for the read-only database.
    #[arg(id = "db-ro-url", long, env = ENV_DB_RO_URL)]
    pub url: Option<String>,
    #[arg(id = "db-ro-user", long, env = ENV_DB_RO_USER)]
    pub username: Option<String>,
    #[arg(id = "db-ro-password", long, env = ENV_DB_RO_PASS)]
    pub password: Option<Hide<String>>,
    #[arg(id = "db-ro-host", long, env = ENV_DB_RO_HOST)]
    pub host: Option<String>,
    #[arg(id = "db-ro-port", long, env = ENV_DB_RO_PORT)]
    pub port: Option<u16>,
    #[arg(id = "db-ro-name", long, env = ENV_DB_RO_NAME)]
    pub name: Option<String>,
    #[arg(id = "db-ro-max-conn", long, env = ENV_DB_RO_MAX_CONN)]
    pub max_conn: Option<u32>,
    #[arg(id = "db-ro-min-conn", long, env = ENV_DB_RO_MIN_CONN)]
    pub min_conn: Option<u32>,
    #[arg(id = "db-ro-sslmode", long, env = ENV_DB_RO_SSLMODE, value_enum)]
    pub sslmode: Option<SslMode>,
    #[arg(id = "db-ro-conn-timeout", long, env = ENV_DB_RO_CONNECT_TIMEOUT)]
    pub connect_timeout: Option<u64>,
    #[arg(id = "db-ro-acquire-timeout", long, env = ENV_DB_RO_ACQUIRE_TIMEOUT)]
    pub acquire_timeout: Option<u64>,
    #[arg(id = "db-ro-max-lifetime", long, env = ENV_DB_RO_MAX_LIFETIME)]
    pub max_lifetime: Option<u64>,
    #[arg(id = "db-ro-idle-timeout", long, env = ENV_DB_RO_IDLE_TIMEOUT)]
    pub idle_timeout: Option<u64>,
}

impl DatabaseReadOnly {
    /// Builds a `Database` config by overlaying R/O values on top of the R/W fallback.
    ///
    /// Fails when a read-only URL is supplied while IAM authentication is inherited from the
    /// R/W config. IAM authentication injects a short-lived token as the password over a
    /// connection built from the discrete host/port/user fields, so a complete DSN cannot
    /// carry it — the same reason the R/W config forbids combining `--db-url` with
    /// `--db-iam-auth`. Rejecting here (rather than silently dropping the URL and reusing the
    /// R/W host, which would misroute reads to the primary) surfaces the misconfiguration with
    /// an actionable message.
    pub fn to_database_config(&self, fallback: &Database) -> Result<Database, anyhow::Error> {
        if fallback.iam_auth && self.url.is_some() {
            return Err(anyhow!(
                "'--db-ro-url' ({ENV_DB_RO_URL}) cannot be combined with IAM authentication \
                 (inherited from the read-write config); configure the read-only database with \
                 the discrete '--db-ro-host'/'--db-ro-port'/'--db-ro-user' options instead"
            ));
        }

        Ok(Database {
            url: self.url.clone().or_else(|| fallback.url.clone()),
            username: self
                .username
                .clone()
                .unwrap_or_else(|| fallback.username.clone()),
            password: self
                .password
                .clone()
                .unwrap_or_else(|| fallback.password.clone()),
            host: self.host.clone().unwrap_or_else(|| fallback.host.clone()),
            port: self.port.unwrap_or(fallback.port),
            name: self.name.clone().unwrap_or_else(|| fallback.name.clone()),
            max_conn: self.max_conn.unwrap_or(fallback.max_conn),
            min_conn: self.min_conn.unwrap_or(fallback.min_conn),
            sslmode: self.sslmode.unwrap_or(fallback.sslmode),
            // IAM authentication settings are inherited from the R/W config; a read-only
            // replica reached with IAM auth uses the same mechanism and region.
            iam_auth: fallback.iam_auth,
            region: fallback.region.clone(),
            connect_timeout: self.connect_timeout.unwrap_or(fallback.connect_timeout),
            acquire_timeout: self.acquire_timeout.unwrap_or(fallback.acquire_timeout),
            max_lifetime: self.max_lifetime.unwrap_or(fallback.max_lifetime),
            idle_timeout: self.idle_timeout.unwrap_or(fallback.idle_timeout),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;

    #[test]
    fn url() {
        let result = Database::try_parse_from(["test", "--db-url", "postgres://localhost:4321"])
            .expect("must parse");

        assert_eq!(
            Database {
                url: Some("postgres://localhost:4321".to_string()),
                username: DB_USER.into(),
                password: DB_PASS.into(),
                host: DB_HOST.into(),
                port: DB_PORT,
                name: DB_NAME.into(),
                max_conn: DB_MAX_CONN,
                min_conn: DB_MIN_CONN,
                connect_timeout: DB_CONNECT_TIMEOUT,
                acquire_timeout: DB_ACQUIRE_TIMEOUT,
                max_lifetime: DB_MAX_LIFETIME,
                idle_timeout: DB_IDLE_TIMEOUT,
                sslmode: SslMode::default(),
                iam_auth: false,
                region: None,
            },
            result
        );
    }

    #[test]
    fn args() {
        let result =
            Database::try_parse_from(["test", "--db-sslmode", "disable"]).expect("must parse");

        assert_eq!(
            Database {
                url: None,
                username: DB_USER.into(),
                password: DB_PASS.into(),
                host: DB_HOST.into(),
                port: DB_PORT,
                name: DB_NAME.into(),
                max_conn: DB_MAX_CONN,
                min_conn: DB_MIN_CONN,
                connect_timeout: DB_CONNECT_TIMEOUT,
                acquire_timeout: DB_ACQUIRE_TIMEOUT,
                max_lifetime: DB_MAX_LIFETIME,
                idle_timeout: DB_IDLE_TIMEOUT,
                sslmode: SslMode::Disable,
                iam_auth: false,
                region: None,
            },
            result
        );

        assert_eq!(
            result.to_url(),
            "postgres://postgres:trustify@localhost:5432/trustify?sslmode=disable"
        );
    }

    /// Helper to create a default R/W config for use in R/O fallback tests.
    fn rw_default() -> Database {
        Database {
            url: None,
            username: DB_USER.into(),
            password: DB_PASS.into(),
            host: DB_HOST.into(),
            port: DB_PORT,
            name: DB_NAME.into(),
            max_conn: DB_MAX_CONN,
            min_conn: DB_MIN_CONN,
            connect_timeout: DB_CONNECT_TIMEOUT,
            acquire_timeout: DB_ACQUIRE_TIMEOUT,
            max_lifetime: DB_MAX_LIFETIME,
            idle_timeout: DB_IDLE_TIMEOUT,
            sslmode: SslMode::default(),
            iam_auth: false,
            region: None,
        }
    }

    /// Verify that an unconfigured R/O config falls back to the R/W config entirely.
    #[test]
    fn ro_fallback_uses_rw_config() {
        // given: a default R/W config and an empty R/O config
        let rw = rw_default();
        let ro = DatabaseReadOnly::default();

        // when: building the R/O database config
        let result = ro.to_database_config(&rw).expect("must build");

        // then: the result is identical to the R/W config
        assert_eq!(result, rw);
    }

    /// Verify that individual R/O fields override the R/W fallback while inheriting the rest.
    #[test]
    fn ro_overrides_host_and_port() {
        // given: a default R/W config and an R/O config with host and port set
        let rw = rw_default();
        let ro = DatabaseReadOnly {
            host: Some("replica.example.com".into()),
            port: Some(5433),
            ..Default::default()
        };

        // when: building the R/O database config
        let result = ro.to_database_config(&rw).expect("must build");

        // then: host and port are overridden, everything else falls back to R/W
        assert_eq!(result.host, "replica.example.com");
        assert_eq!(result.port, 5433);
        assert_eq!(result.username, rw.username);
        assert_eq!(result.password, rw.password);
        assert_eq!(result.name, rw.name);
    }

    /// Verify that the R/O URL takes precedence over the R/W URL.
    #[test]
    fn ro_url_overrides_rw_url() {
        // given: both R/W and R/O specify a URL
        let rw = Database {
            url: Some("postgres://primary:5432/trustify".into()),
            ..rw_default()
        };
        let ro = DatabaseReadOnly {
            url: Some("postgres://replica:5433/trustify".into()),
            ..Default::default()
        };

        // when: building the R/O database config
        let result = ro.to_database_config(&rw).expect("must build");

        // then: the R/O URL wins
        assert_eq!(
            result.url.as_deref(),
            Some("postgres://replica:5433/trustify")
        );
    }

    /// Verify that R/O credentials override R/W credentials independently.
    #[test]
    fn ro_separate_credentials() {
        // given: an R/O config that only overrides username and password
        let rw = rw_default();
        let ro = DatabaseReadOnly {
            username: Some("readonly_user".into()),
            password: Some("readonly_pass".into()),
            ..Default::default()
        };

        // when: building the R/O database config
        let result = ro.to_database_config(&rw).expect("must build");

        // then: credentials come from R/O, connection target falls back to R/W
        assert_eq!(result.username, "readonly_user");
        assert_eq!(result.password.0, "readonly_pass");
        assert_eq!(result.host, rw.host);
        assert_eq!(result.port, rw.port);
    }

    /// Verify that supplying a read-only URL while IAM auth is inherited is rejected, since
    /// IAM authentication cannot inject its token into a complete DSN.
    #[test]
    fn ro_url_with_inherited_iam_auth_is_rejected() {
        // given: an IAM-authenticated R/W config and an R/O config that supplies a URL
        let rw = Database {
            iam_auth: true,
            region: Some("us-east-1".into()),
            ..rw_default()
        };
        let ro = DatabaseReadOnly {
            url: Some("postgres://replica:5433/trustify".into()),
            ..Default::default()
        };

        // when: building the R/O database config
        let result = ro.to_database_config(&rw);

        // then: it fails with an actionable error mentioning the R/O URL flag
        let err = result
            .expect_err("must reject R/O URL under IAM auth")
            .to_string();
        assert!(err.contains(ENV_DB_RO_URL), "unexpected error: {err}");
    }

    /// Verify that IAM auth without a read-only URL still builds, inheriting IAM settings and
    /// applying discrete R/O overrides.
    #[test]
    fn ro_discrete_fields_with_inherited_iam_auth_is_allowed() {
        // given: an IAM-authenticated R/W config and an R/O config using discrete fields
        let rw = Database {
            iam_auth: true,
            region: Some("us-east-1".into()),
            ..rw_default()
        };
        let ro = DatabaseReadOnly {
            host: Some("replica.example.com".into()),
            ..Default::default()
        };

        // when: building the R/O database config
        let result = ro.to_database_config(&rw).expect("must build");

        // then: IAM settings are inherited and the discrete host override is applied
        assert!(result.iam_auth);
        assert_eq!(result.region.as_deref(), Some("us-east-1"));
        assert_eq!(result.host, "replica.example.com");
        assert_eq!(result.url, None);
    }
}
