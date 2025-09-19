use clap::Parser;
use migration::{
    Migrator,
    data::{Direction, MigratorWithData, Options, Runner},
};
use trustify_module_storage::config::StorageConfig;

#[derive(clap::Parser, Debug, Clone)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
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

impl Run {
    fn direction(&self) -> Direction {
        if self.down {
            Direction::Down
        } else {
            self.direction
        }
    }

    #[allow(clippy::expect_used)]
    pub async fn run(self) -> anyhow::Result<()> {
        let direction = self.direction();
        let storage = self.storage.into_storage(false).await?;

        Runner {
            direction,
            storage,
            migrations: self.migrations,
            database_url: self
                .database_url
                .expect("Environment variable 'DATABASE_URL' not set"),
            database_schema: self.database_schema,
            options: self.options,
        }
        .run::<Migrator>()
        .await?;

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

#[allow(clippy::unwrap_used)]
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    cli.command.run().await.unwrap();
}
