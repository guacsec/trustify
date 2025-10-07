use migration::data::{Direction, Options, Runner};
use postgresql_embedded::{PostgreSQL, VersionReq};
use std::{collections::HashMap, env, fs::create_dir_all, process::ExitCode, time::Duration};
use trustify_common::{config::Database, db};
use trustify_infrastructure::otel::{Tracing, init_tracing};
use trustify_module_storage::config::StorageConfig;

#[derive(clap::Args, Debug)]
pub struct Run {
    #[command(subcommand)]
    pub(crate) command: Command,
    #[command(flatten)]
    pub(crate) database: Database,
}

#[derive(clap::Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Create database
    Create,
    /// Run migrations (up)
    Migrate,
    /// Remove all migrations and re-apply them (DANGER)
    Refresh,
    /// Run specific data migrations
    Data(Data),
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        init_tracing("db-run", Tracing::Disabled);
        use Command::*;
        match self.command {
            Create => self.create().await,
            Migrate => self.migrate().await,
            Refresh => self.refresh().await,
            Data(data) => data.run(Direction::Up, self.database).await,
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

#[derive(clap::Args, Debug, Clone)]
pub struct Data {
    /// Migrations to run
    #[arg()]
    name: Vec<String>,
    #[command(flatten)]
    storage: StorageConfig,
    #[command(flatten)]
    options: Options,
}

impl Data {
    pub async fn run(self, direction: Direction, database: Database) -> anyhow::Result<ExitCode> {
        let Self {
            name: migrations,
            storage,
            options,
        } = self;

        match db::Database::new(&database).await {
            Ok(db) => {
                trustify_db::Database(&db)
                    .data_migrate(Runner {
                        database_url: database.to_url(),
                        database_schema: None,
                        storage: storage.into_storage(false).await?,
                        direction,
                        migrations,
                        options,
                    })
                    .await?;
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => Err(e),
        }
    }
}
