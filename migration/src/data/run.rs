use crate::data::{MigratorWithData, Options, SchemaDataManager};
use anyhow::bail;
use sea_orm::ConnectOptions;
use sea_orm_migration::{IntoSchemaManagerConnection, SchemaManager};
use std::{collections::HashMap, time::SystemTime};
use trustify_module_storage::service::dispatch::DispatchBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Direction {
    #[default]
    Up,
    Down,
}

pub struct Runner {
    pub database: Database,
    pub storage: DispatchBackend,
    pub direction: Direction,
    pub migrations: Vec<String>,
    pub options: Options,
}

pub enum Database {
    Config { url: String, schema: Option<String> },
    Provided(sea_orm::DatabaseConnection),
}

impl Runner {
    pub async fn run<M: MigratorWithData>(self) -> anyhow::Result<()> {
        let migrations = M::data_migrations()
            .into_iter()
            .map(|migration| (migration.name().to_string(), migration))
            .collect::<HashMap<_, _>>();

        let mut running = vec![];

        for migration in self.migrations {
            let Some(migration) = migrations.get(&migration) else {
                bail!("Migration '{migration}' not found");
            };
            running.push(migration);
        }

        let database = match self.database {
            Database::Config { url, schema } => {
                let schema = schema.unwrap_or_else(|| "public".to_owned());

                let connect_options = ConnectOptions::new(url)
                    .set_schema_search_path(schema)
                    .to_owned();

                sea_orm::Database::connect(connect_options).await?
            }
            Database::Provided(database) => database,
        };

        let manager = SchemaManager::new(database.into_schema_manager_connection());
        let manager = SchemaDataManager::new(&manager, &self.storage, &self.options);

        for run in running {
            tracing::info!(name = run.name(), "Running data migration");

            let start = SystemTime::now();

            match self.direction {
                Direction::Up => run.up(&manager).await?,
                Direction::Down => run.down(&manager).await?,
            }

            if let Ok(duration) = start.elapsed() {
                tracing::info!(
                    name = run.name(),
                    "Took {}",
                    humantime::Duration::from(duration)
                )
            }
        }

        Ok(())
    }
}
