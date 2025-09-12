use anyhow::bail;
use clap::Parser;
use migration::{Migrator, Options, SchemaDataManager};
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::{IntoSchemaManagerConnection, SchemaManager};
use std::collections::HashMap;
use trustify_module_storage::config::StorageConfig;

#[derive(clap::Parser, Debug, Clone)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug, Clone)]
enum Command {
    /// List all data migrations
    List,
    /// Run a list of migrations
    Run(Run),
}

#[derive(clap::Args, Debug, Clone)]
struct Run {
    /// Migration direction to run
    #[arg(
        long,
        value_enum,
        default_value_t = Direction::Up,
        overrides_with = "down"
    )]
    direction: Direction,

    /// Shortcut for `--direction down`
    #[arg(long, action = clap::ArgAction::SetTrue, overrides_with = "direction")]
    down: bool,

    // from sea_orm
    #[arg(
        global = true,
        short = 's',
        long,
        env = "DATABASE_SCHEMA",
        long_help = "Database schema\n \
                    - For MySQL and SQLite, this argument is ignored.\n \
                    - For PostgreSQL, this argument is optional with default value 'public'.\n"
    )]
    database_schema: Option<String>,

    // from sea_orm
    #[arg(
        global = true,
        short = 'u',
        long,
        env = "DATABASE_URL",
        help = "Database URL"
    )]
    database_url: Option<String>,

    #[arg()]
    migrations: Vec<String>,

    #[command(flatten)]
    options: Options,

    #[command(flatten)]
    storage: StorageConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Direction {
    #[default]
    Up,
    Down,
}

impl Run {
    fn direction(&self) -> Direction {
        if self.down {
            Direction::Down
        } else {
            self.direction
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let direction = self.direction();

        let migrations = Migrator::data_migrations()
            .into_iter()
            .map(|migration| (migration.name().to_string(), migration))
            .collect::<HashMap<_, _>>();

        let mut running = vec![];

        for migration in self.migrations {
            let Some(migration) = migrations.get(&migration) else {
                bail!("Migration {migration} not found");
            };
            running.push(migration);
        }

        let storage = self.storage.into_storage(false).await?;

        let url = self
            .database_url
            .expect("Environment variable 'DATABASE_URL' not set");
        let schema = self.database_schema.unwrap_or_else(|| "public".to_owned());

        let connect_options = ConnectOptions::new(url)
            .set_schema_search_path(schema)
            .to_owned();

        let db = Database::connect(connect_options).await?;

        let manager = SchemaManager::new(db.into_schema_manager_connection());
        let manager = SchemaDataManager::new(&manager, &storage, &self.options);

        for run in running {
            tracing::info!("Running data migration: {}", run.name());

            match direction {
                Direction::Up => run.up(&manager).await?,
                Direction::Down => run.down(&manager).await?,
            }
        }

        Ok(())
    }
}

impl Command {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Command::Run(run) => run.run().await,
            Command::List => {
                for m in Migrator::data_migrations() {
                    println!("{}", m.name());
                }
                Ok(())
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    cli.command.run().await.unwrap();
}
