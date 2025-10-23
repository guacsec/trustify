pub mod embedded;

use anyhow::{Context, anyhow, ensure};
use migration::Migrator;
use postgresql_commands::{CommandBuilder, psql::PsqlBuilder};
use sea_orm::{ConnectionTrait, Statement};
use sea_orm_migration::prelude::MigratorTrait;
use std::process::Stdio;
use tokio::io::{self, AsyncRead, AsyncWriteExt};
use tracing::instrument;
use trustify_common::{config, db};

pub struct Database<'a>(pub &'a db::Database);

impl<'a> Database<'a> {
    #[instrument(skip(self), err)]
    pub async fn migrate(&self) -> Result<(), anyhow::Error> {
        log::debug!("applying migrations");
        Migrator::up(self.0, None).await?;
        log::debug!("applied migrations");

        Ok(())
    }

    #[instrument(skip(self), err)]
    pub async fn refresh(&self) -> Result<(), anyhow::Error> {
        log::warn!("refreshing database schema...");
        Migrator::refresh(self.0).await?;
        log::warn!("refreshing database schema... done!");

        Ok(())
    }

    /// Import a database from a provided DB dump.
    #[instrument(err)]
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
            format!("CREATE DATABASE \"{}\";", database.name),
        ))
        .await?;
        db.close().await?;

        let db = db::Database::new(database).await?;
        db.execute_unprepared("CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\";")
            .await?;

        Ok(db)
    }

    #[instrument(err)]
    pub async fn bootstrap(database: &config::Database) -> Result<db::Database, anyhow::Error> {
        let db = Self::setup(database).await?;

        Database(&db).migrate().await?;

        Ok(db)
    }

    /// Import a database from a provided DB dump.
    #[instrument(skip(r), err)]
    pub async fn import<R>(
        database: &config::Database,
        mut r: R,
    ) -> Result<db::Database, anyhow::Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let db = Self::setup(database).await?;

        let mut cmd = PsqlBuilder::new()
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
}
