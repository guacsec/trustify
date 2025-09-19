use crate::data::{MigratorWithData, Options, SchemaDataManager};
use anyhow::bail;
use sea_orm::{ConnectOptions, Database};
use sea_orm_migration::{IntoSchemaManagerConnection, SchemaManager};
use std::collections::HashMap;
use trustify_module_storage::service::dispatch::DispatchBackend;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Direction {
    #[default]
    Up,
    Down,
}

pub struct Runner {
    pub database_url: String,
    pub database_schema: Option<String>,
    pub storage: DispatchBackend,
    pub direction: Direction,
    pub migrations: Vec<String>,
    pub options: Options,
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

        let schema = self.database_schema.unwrap_or_else(|| "public".to_owned());

        let connect_options = ConnectOptions::new(self.database_url)
            .set_schema_search_path(schema)
            .to_owned();

        let db = Database::connect(connect_options).await?;

        let manager = SchemaManager::new(db.into_schema_manager_connection());
        let manager = SchemaDataManager::new(&manager, &self.storage, &self.options);

        for run in running {
            tracing::info!(name = run.name(), "Running data migration");

            match self.direction {
                Direction::Up => run.up(&manager).await?,
                Direction::Down => run.down(&manager).await?,
            }
        }

        Ok(())
    }
}
