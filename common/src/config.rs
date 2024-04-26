use std::env;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Database")]
#[group(id = "database")]
pub struct Database {
    #[arg(id = "db-user", long, env = "DB_USER", default_value = "trustify")]
    pub username: String,
    #[arg(
        id = "db-password",
        long,
        env = "DB_PASSWORD",
        default_value = "trustify"
    )]
    pub password: String,
    #[arg(id = "db-host", long, env = "DB_HOST", default_value = "localhost")]
    pub host: String,
    #[arg(id = "db-port", long, env = "DB_PORT", default_value_t = 5432)]
    pub port: u16,
    #[arg(id = "db-name", long, env = "DB_NAME", default_value = "trustify")]
    pub name: String,
}

// TODO: figure out how to make clap use this and remove the redundant
// #[arg(...)]'s above
impl Default for Database {
    fn default() -> Self {
        Database {
            username: env::var("DB_USER").unwrap_or("trustify".into()),
            password: env::var("DB_PASSWORD").unwrap_or("trustify".into()),
            host: env::var("DB_HOST").unwrap_or("localhost".into()),
            port: env::var("DB_PORT")
                .unwrap_or("5432".into())
                .parse::<u16>()
                .expect("Port should be an integer"),
            name: env::var("DB_NAME").unwrap_or("trustify".into()),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum StorageStrategy {
    Fs,
    S3,
}

impl Display for StorageStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageStrategy::Fs => write!(f, "fs"),
            StorageStrategy::S3 => write!(f, "s3"),
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Storage")]
#[group(id = "storage", multiple = false)]
pub struct StorageConfig {
    #[arg(
        id = "storage-strategy",
        long,
        env,
        default_value_t = StorageStrategy::Fs,
    )]
    pub storage_strategy: StorageStrategy,

    #[arg(
        id = "storage-fs-path",
        long,
        env = "DB_NAME",
        default_value = "./.trustify/storage",
        required = false,
        required_if_eq("storage-strategy", "fs")
    )]
    pub fs_path: Option<PathBuf>,
}
