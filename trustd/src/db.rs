use postgresql_embedded::{PostgreSQL, VersionReq};
use std::{collections::HashMap, env, fs::create_dir_all, process::ExitCode, time::Duration};
use trustify_common::{config::Database, db};
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
    Migrate,
    Refresh,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        init_tracing("db-run", Tracing::Disabled);
        use Command::*;
        match self.command {
            Create => self.create().await,
            Migrate => self.migrate().await,
            Refresh => self.refresh().await,
        }
    }

    async fn create(self) -> anyhow::Result<ExitCode> {
        match trustify_db::Database::bootstrap(&self.database).await {
            Ok(_) => Ok(ExitCode::SUCCESS),
            Err(e) => Err(e),
        }
    }

    async fn refresh(self) -> anyhow::Result<ExitCode> {
        match db::Database::new(&self.database).await {
            Ok(db) => {
                trustify_db::Database(&db).refresh().await?;
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => Err(e),
        }
    }

    async fn migrate(self) -> anyhow::Result<ExitCode> {
        match db::Database::new(&self.database).await {
            Ok(db) => {
                trustify_db::Database(&db).migrate().await?;
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
