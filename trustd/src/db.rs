use postgresql_embedded::{PostgreSQL, VersionReq};
use std::collections::HashMap;
use std::env;
use std::fs::create_dir_all;
use std::process::ExitCode;
use std::time::Duration;
use trustify_common::config::Database;
use trustify_common::db;
use trustify_infrastructure::otel::{Tracing, init_tracing};

#[derive(clap::Args, Debug)]
pub struct Run {
    #[command(subcommand)]
    pub(crate) command: Command,
    #[command(flatten)]
    pub(crate) database: Database,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Create,
    Migrate {
        /// Run migrations up to and including the named migration, then stop.
        /// Accepts a full or partial migration name (e.g. "m0002120_sbom_ancestor" or "sbom_ancestor").
        #[arg(long)]
        up_to: Option<String>,
    },
    Refresh,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        init_tracing("db-run", Tracing::Disabled);
        let Run { command, database } = self;
        match command {
            Command::Create => Run::create(database).await,
            Command::Migrate { up_to } => Run::migrate(database, up_to).await,
            Command::Refresh => Run::refresh(database).await,
        }
    }

    async fn create(database: Database) -> anyhow::Result<ExitCode> {
        match trustify_db::Database::bootstrap(&database).await {
            Ok(_) => Ok(ExitCode::SUCCESS),
            Err(e) => Err(e),
        }
    }
    async fn refresh(database: Database) -> anyhow::Result<ExitCode> {
        match db::Database::new(&database).await {
            Ok(db) => {
                trustify_db::Database(&db).refresh().await?;
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => Err(e),
        }
    }
    /// Apply database migrations, optionally stopping at a specific migration.
    async fn migrate(database: Database, up_to: Option<String>) -> anyhow::Result<ExitCode> {
        match db::Database::new(&database).await {
            Ok(db) => {
                let db = trustify_db::Database(&db);
                match up_to {
                    Some(name) => db.migrate_up_to(&name).await?,
                    None => db.migrate().await?,
                }
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<PostgreSQL> {
        init_tracing("db-start", Tracing::Disabled);
        log::warn!("Setting up managed DB; not suitable for production use!");

        let current_dir = env::current_dir()?;
        let work_dir = current_dir.join(".trustify");
        let db_dir = work_dir.join("postgres");
        let data_dir = work_dir.join("data");
        create_dir_all(&data_dir)?;
        let configuration = HashMap::from([
            (
                "shared_preload_libraries".to_string(),
                "pg_stat_statements".to_string(),
            ),
            ("random_page_cost".to_string(), "1.1".to_string()),
            (
                "max_parallel_workers_per_gather".to_string(),
                "4".to_string(),
            ),
            ("max_connections".to_string(), "500".to_string()),
        ]);
        let settings = postgresql_embedded::Settings {
            version: VersionReq::parse("=17.2.0")?,
            username: self.database.username.clone(),
            password: self.database.password.clone().into(),
            temporary: false,
            installation_dir: db_dir.clone(),
            timeout: Some(Duration::from_secs(30)),
            configuration,
            data_dir,
            ..Default::default()
        };
        let mut postgresql = PostgreSQL::new(settings);
        postgresql.setup().await?;
        postgresql.start().await?;

        let port = postgresql.settings().port;
        self.database.port = port;

        log::info!("PostgreSQL installed in {db_dir:?}");
        log::info!("Running on port {port}");

        Ok(postgresql)
    }
}
