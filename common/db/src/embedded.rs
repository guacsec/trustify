use anyhow::Context;
use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{Instrument, info_span};
use trustify_common::{db::Database, decompress::decompress_async_read};

/// Create common default settings for the embedded database
pub fn default_settings() -> anyhow::Result<Settings> {
    // **NOTE:** Changing the default version here, one should also change the env-var in the CI job
    let version = VersionReq::parse(option_env!("POSTGRESQL_VERSION").unwrap_or("=17.2.0"))
        .context("valid psql version")?;
    Ok(Settings {
        version,
        username: "postgres".to_string(),
        password: "trustify".to_string(),
        temporary: true,
        // The default of 5s is not enough for `initdb` (and the other commands) on a loaded CI
        // runner, where several test binaries bring up their own instance in parallel.
        timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    })
}

/// Create a new, embedded database instance
pub async fn create() -> anyhow::Result<(Database, PostgreSQL)> {
    create_for(default_settings()?, Default::default()).await
}

/// Create a new, embedded database instance in a specific directory
pub async fn create_in(base: impl AsRef<Path>) -> anyhow::Result<(Database, PostgreSQL)> {
    let base = base.as_ref();

    create_for(
        Settings {
            data_dir: base.join("data"),
            installation_dir: base.join("instance"),
            ..default_settings()?
        },
        Default::default(),
    )
    .await
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

/// Create a new, embedded database instance, using the provided settings
pub async fn create_for(
    settings: Settings,
    options: Options,
) -> anyhow::Result<(Database, PostgreSQL)> {
    log::info!("creating embedded database - version: {}", settings.version);

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

    let db = match options.source {
        Source::Bootstrap => super::Database::bootstrap(&config)
            .await
            .context("Bootstrapping the test database")?,
        Source::Import(path) => {
            log::info!("Importing database from: {}", path.display());

            let source = decompress_async_read(path).await?;

            super::Database::import(&config, source)
                .await
                .context("Bootstrapping the test database")?
        }
    };

    Ok((db, postgresql))
}
