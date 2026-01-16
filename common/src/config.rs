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
        })
    }

    pub fn to_url(&self) -> String {
        if let Some(url) = &self.url {
            return url.clone();
        }

        format!(
            "postgres://{username}:{password}@{host}:{port}/{db_name}?sslmode={sslmode}",
            username = &self.username,
            password = &self.password.0,
            host = &self.host,
            port = self.port,
            db_name = &self.name,
            sslmode = &self.sslmode,
        )
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
            },
            result
        );

        assert_eq!(
            result.to_url(),
            "postgres://postgres:trustify@localhost:5432/trustify?sslmode=disable"
        );
    }
}
