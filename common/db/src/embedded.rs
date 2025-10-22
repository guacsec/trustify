use anyhow::Context;
use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
use std::{
    path::{Path, PathBuf},
    pin::Pin,
};
use tokio::io::{AsyncRead, BufReader};
use tracing::{Instrument, info_span};
use trustify_common::db::Database;

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

    let config = crate::config::Database {
        username: "postgres".into(),
        password: "trustify".into(),
        host: "localhost".into(),
        name: "test".into(),
        port: postgresql.settings().port,
        ..crate::config::Database::from_env()?
    };

    let db = match options.source {
        Source::Bootstrap => super::Database::bootstrap(&config)
            .await
            .context("Bootstrapping the test database")?,
        Source::Import(path) => {
            log::info!("Importing from: {}", path.display());

            let source = tokio::fs::File::open(&path).await?;
            let source = BufReader::new(source);

            let source: Pin<Box<dyn AsyncRead + Send>> = match path
                .extension()
                .and_then(|ext| ext.to_str())
            {
                None | Some("sql") => Box::pin(source),
                Some("xz") => Box::pin(async_compression::tokio::bufread::LzmaDecoder::new(source)),
                Some(ext) => anyhow::bail!("Unsupported file type ({ext})"),
            };

            super::Database::import(&config, source)
                .await
                .context("Bootstrapping the test database")?
        }
    };

    Ok((db, postgresql))
}
