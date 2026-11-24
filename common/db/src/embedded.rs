use anyhow::Context;
use migration::Migrator;
use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use tracing::{Instrument, info_span};
use trustify_common::{db::Database, decompress::decompress_async_read};

/// PostgreSQL server settings for an embedded database.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct PostgresArgs {
    /// Configure embedded PostgreSQL (e.g. max_wal_size=4GB). May be repeated.
    ///
    /// Separate assignments in the environment variable with commas.
    /// Later assignments to the same setting win.
    #[arg(
        long = "pg-setting",
        env = "TRUSTD_EMBEDDED_PG_SETTINGS",
        value_name = "NAME=VALUE",
        value_delimiter = ','
    )]
    pub settings: Vec<PostgresSetting>,
}

impl PostgresArgs {
    /// Apply overrides before starting PostgreSQL, preserving other settings.
    pub fn apply(self, settings: &mut Settings) {
        settings.configuration.extend(
            self.settings
                .into_iter()
                .map(|setting| (setting.name, setting.value)),
        );
    }
}

/// A PostgreSQL server setting written as `NAME=VALUE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresSetting {
    pub name: String,
    pub value: String,
}

impl FromStr for PostgresSetting {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.split_once('=') {
            Some((name, value)) if !name.trim().is_empty() && !value.trim().is_empty() => {
                Ok(Self {
                    name: name.to_owned(),
                    value: value.to_owned(),
                })
            }
            _ => Err("expected NAME=VALUE with a nonempty name and value".into()),
        }
    }
}

/// Create common default settings for the embedded database
pub fn default_settings() -> anyhow::Result<Settings> {
    // **NOTE:** Changing the default version here, one should also change the env-var in the CI job
    let version = VersionReq::parse(option_env!("POSTGRESQL_VERSION").unwrap_or("=17.2.1"))
        .context("valid psql version")?;
    Ok(Settings {
        version,
        username: "postgres".to_string(),
        password: "trustify".to_string(),
        temporary: true,
        // Allow time for embedded PostgreSQL operations on busy CI runners.
        timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    })
}

#[derive(Default, Debug)]
pub enum Source {
    #[default]
    Bootstrap,
    Import(PathBuf),
}

#[derive(Default, Debug)]
pub struct Options {
    pub source: Source,
}

/// Configure and create an embedded PostgreSQL database.
#[derive(Debug)]
pub struct Builder {
    settings: Settings,
    source: Source,
}

impl From<Settings> for Builder {
    fn from(settings: Settings) -> Self {
        Self {
            settings,
            source: Source::default(),
        }
    }
}

impl Builder {
    /// Start with the shared embedded PostgreSQL defaults.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self::from(default_settings()?))
    }

    /// Keep the database and PostgreSQL installation below this directory.
    pub fn dir(mut self, base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        self.settings.data_dir = base.join("data");
        self.settings.installation_dir = base.join("instance");
        self
    }

    /// Change only the data directory, retaining the PostgreSQL installation location.
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.settings.data_dir = path.into();
        self
    }

    /// Customize PostgreSQL settings before startup.
    pub fn configure(mut self, configure: impl FnOnce(&mut Settings)) -> Self {
        configure(&mut self.settings);
        self
    }

    /// Apply PostgreSQL server arguments before startup.
    pub fn args(self, args: PostgresArgs) -> Self {
        self.configure(|settings| args.apply(settings))
    }

    /// Bootstrap a new database or import an existing dump.
    pub fn source(mut self, source: Source) -> Self {
        self.source = source;
        self
    }

    /// Inspect the settings that will be used at startup.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Start PostgreSQL and prepare the database.
    pub async fn create(self, migrator: &Migrator) -> anyhow::Result<(Database, PostgreSQL)> {
        let Self { settings, source } = self;
        tracing::info!("creating embedded database - version: {}", settings.version);

        let postgresql = async {
            let mut postgresql = PostgreSQL::new(settings);
            postgresql
                .setup()
                .await
                .context("Setting up the test database")?;
            postgresql
                .start()
                .await
                .context("Starting the test database")?;
            Ok::<_, anyhow::Error>(postgresql)
        }
        .instrument(info_span!("start database"))
        .await?;

        let config = crate::config::Database::from_port(postgresql.settings().port)?;

        let db = match source {
            Source::Bootstrap => super::Database::bootstrap(&config, migrator)
                .await
                .context("Bootstrapping the test database")?,
            Source::Import(path) => {
                tracing::info!("Importing database from: {}", path.display());

                let source = decompress_async_read(path).await?;

                super::Database::import(&config, source)
                    .await
                    .context("Bootstrapping the test database")?
            }
        };

        Ok((db, postgresql))
    }
}

/// Create a new, embedded database instance.
pub async fn create(migrator: &Migrator) -> anyhow::Result<(Database, PostgreSQL)> {
    Builder::new()?.create(migrator).await
}

/// Create a new, embedded database instance in a specific directory.
pub async fn create_in(
    base: impl AsRef<Path>,
    migrator: &Migrator,
) -> anyhow::Result<(Database, PostgreSQL)> {
    Builder::new()?.dir(base).create(migrator).await
}

/// Create a new, embedded database instance, using the provided settings.
pub async fn create_for(
    settings: Settings,
    options: Options,
    migrator: &Migrator,
) -> anyhow::Result<(Database, PostgreSQL)> {
    Builder::from(settings)
        .source(options.source)
        .create(migrator)
        .await
}
