pub mod embedded;

use anyhow::{Context, anyhow, ensure};
use migration::Migrator;
use migration::data::Runner;
use postgresql_commands::{CommandBuilder, psql::PsqlBuilder};
use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::{MigrationTrait, MigratorTrait};
use std::process::Stdio;
use tokio::io::{self, AsyncRead, AsyncWriteExt};
use tracing::instrument;
use trustify_common::{config, db};

pub struct Database<'a>(pub &'a db::Database);

impl<'a> Database<'a> {
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn migrate(&self) -> Result<(), anyhow::Error> {
        log::debug!("applying migrations");
        Migrator::up(self.0, None).await?;
        log::debug!("applied migrations");

        Ok(())
    }

    /// Apply migrations up to and including the one matching the given name.
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn migrate_up_to(&self, name: &str) -> Result<(), anyhow::Error> {
        let all_migrations = Migrator::migrations();

        let target_pos = find_migration_position(&all_migrations, name)?;
        let target_name = all_migrations[target_pos].name().to_string();

        let applied = Migrator::get_applied_migrations(self.0).await?;
        let applied_count = applied.len() as u32;
        let target_count = (target_pos as u32) + 1;

        if target_count <= applied_count {
            log::info!("migration '{target_name}' is already applied");
            return Ok(());
        }

        let steps = target_count - applied_count;
        log::debug!("applying {steps} migration(s) up to '{target_name}'");
        Migrator::up(self.0, Some(steps)).await?;
        log::debug!("applied migrations up to '{target_name}'");

        Ok(())
    }

    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn refresh(&self) -> Result<(), anyhow::Error> {
        log::warn!("refreshing database schema...");
        Migrator::refresh(self.0).await?;
        log::warn!("refreshing database schema... done!");

        Ok(())
    }

    /// Import a database from a provided DB dump.
    #[instrument(err(level=tracing::Level::INFO))]
    pub async fn setup(database: &config::Database) -> Result<db::Database, anyhow::Error> {
        ensure!(
            database.url.is_none(),
            "Unable to bootstrap database with '--db-url'"
        );

        let url = config::Database {
            name: "postgres".into(),
            ..database.clone()
        }
        .to_url();

        let db = sea_orm::Database::connect(url).await?;

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!("DROP DATABASE IF EXISTS \"{}\";", database.name),
        ))
        .await?;

        db.execute(Statement::from_string(
            db.get_database_backend(),
            format!(
                "CREATE DATABASE \"{}\" WITH LC_COLLATE 'C' TEMPLATE 'template0';",
                database.name
            ),
        ))
        .await?;
        db.close().await?;

        let db = db::Database::new(database).await?;
        db.execute_unprepared("CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\";")
            .await?;

        Ok(db)
    }

    #[instrument(err(level=tracing::Level::INFO))]
    pub async fn bootstrap(database: &config::Database) -> Result<db::Database, anyhow::Error> {
        let db = Self::setup(database).await?;

        Database(&db).migrate().await?;

        Ok(db)
    }

    /// Import a database from a provided DB dump.
    #[instrument(skip(r), err(level=tracing::Level::INFO))]
    pub async fn import<R>(
        database: &config::Database,
        mut r: R,
    ) -> Result<db::Database, anyhow::Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let db = Self::setup(database).await?;

        let mut cmd = PsqlBuilder::new()
            .quiet() // or .output("/dev/null") to remove set_config noise
            .dbname(&database.name)
            .host(&database.host)
            .port(database.port)
            .username(&database.username)
            .pg_password(&database.password.0)
            .build_tokio();

        let mut child = cmd.stdin(Stdio::piped()).spawn()?;

        let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("Missing stdin"))?;
        tokio::spawn(async move {
            io::copy(&mut r, &mut stdin).await.context("copy failed")?;

            let _ = stdin.shutdown().await;

            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let _ = child.wait_with_output().await?;

        // some maintenance after import

        db.execute_unprepared(r#"VACUUM FULL ANALYZE"#).await?;
        db.execute_unprepared(r#"REINDEX database"#).await?;

        // we do not migrate the database here automatically

        Ok(db)
    }

    pub async fn data_migrate(&self, runner: Runner) -> Result<(), anyhow::Error> {
        runner.run::<Migrator>().await
    }
}

/// Find a migration's position by name, trying exact match first, then substring.
fn find_migration_position(
    migrations: &[Box<dyn MigrationTrait>],
    name: &str,
) -> Result<usize, anyhow::Error> {
    if let Some(pos) = migrations.iter().position(|m| m.name() == name) {
        return Ok(pos);
    }

    let matches: Vec<(usize, String)> = migrations
        .iter()
        .enumerate()
        .filter(|(_, m)| m.name().contains(name))
        .map(|(i, m)| (i, m.name().to_string()))
        .collect();

    match matches.len() {
        0 => anyhow::bail!("no migration found matching '{name}'"),
        1 => Ok(matches[0].0),
        _ => {
            let names: Vec<&str> = matches.iter().map(|(_, n)| n.as_str()).collect();
            anyhow::bail!(
                "ambiguous migration name '{name}', matches: {}",
                names.join(", ")
            );
        }
    }
}
