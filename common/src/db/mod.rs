mod func;

pub mod chunk;
pub mod limiter;
pub mod query;

pub mod multi_model;

use anyhow::Context;
use migration::{Migrator, MigratorTrait};
use sea_orm::{
    prelude::async_trait, ConnectOptions, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, ExecResult, QueryResult, RuntimeErr, Statement,
};
use sqlx::error::ErrorKind;
use std::ops::{Deref, DerefMut};
use tracing::instrument;

pub use func::*;

pub enum Transactional {
    None,
    Some(DatabaseTransaction),
}

impl Transactional {
    /// Commit the database transaction.
    ///
    /// If there's no underlying database transaction, then this becomes a no-op.
    #[instrument(skip_all, fields(transactional=matches!(self, Transactional::Some(_))))]
    pub async fn commit(self) -> Result<(), DbErr> {
        match self {
            Transactional::None => {}
            Transactional::Some(inner) => {
                inner.commit().await?;
            }
        }

        Ok(())
    }
}

impl AsRef<Transactional> for Transactional {
    fn as_ref(&self) -> &Transactional {
        self
    }
}

impl AsRef<Transactional> for () {
    fn as_ref(&self) -> &Transactional {
        &Transactional::None
    }
}

#[derive(Clone)]
pub enum ConnectionOrTransaction<'db> {
    Connection(&'db DatabaseConnection),
    Transaction(&'db DatabaseTransaction),
}

#[async_trait::async_trait]
impl ConnectionTrait for ConnectionOrTransaction<'_> {
    fn get_database_backend(&self) -> DbBackend {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.get_database_backend(),
            ConnectionOrTransaction::Transaction(inner) => inner.get_database_backend(),
        }
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.execute(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.execute(stmt).await,
        }
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.execute_unprepared(sql).await,
            ConnectionOrTransaction::Transaction(inner) => inner.execute_unprepared(sql).await,
        }
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.query_one(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.query_one(stmt).await,
        }
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        match self {
            ConnectionOrTransaction::Connection(inner) => inner.query_all(stmt).await,
            ConnectionOrTransaction::Transaction(inner) => inner.query_all(stmt).await,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Database {
    db: DatabaseConnection,
}

impl Database {
    pub fn connection<'db, TX: AsRef<Transactional>>(
        &'db self,
        tx: &'db TX,
    ) -> ConnectionOrTransaction {
        match tx.as_ref() {
            Transactional::None => ConnectionOrTransaction::Connection(&self.db),
            Transactional::Some(tx) => ConnectionOrTransaction::Transaction(tx),
        }
    }

    pub async fn new(database: &crate::config::Database) -> Result<Self, anyhow::Error> {
        let username = &database.username;
        let password = &database.password;
        let host = &database.host;
        let port = database.port;
        let db_name = &database.name;
        let url = format!("postgres://{username}:{password}@{host}:{port}/{db_name}");
        log::debug!("connect to {}", url);

        let mut opt = ConnectOptions::new(url);
        opt.max_connections(300);
        opt.min_connections(75);
        opt.sqlx_logging_level(log::LevelFilter::Trace);

        let db = sea_orm::Database::connect(opt).await?;

        Ok(Self { db })
    }

    #[instrument]
    pub async fn migrate(&self) -> Result<(), anyhow::Error> {
        log::debug!("applying migrations");
        Migrator::up(&self.db, None).await?;
        log::debug!("applied migrations");

        Ok(())
    }

    #[instrument]
    pub async fn refresh(&self) -> Result<(), anyhow::Error> {
        log::warn!("refreshing database schema...");
        Migrator::refresh(&self.db).await?;
        log::warn!("refreshing database schema... done!");

        Ok(())
    }

    #[instrument]
    pub async fn bootstrap(database: &crate::config::Database) -> Result<Self, anyhow::Error> {
        let url = format!(
            "postgres://{}:{}@{}:{}/postgres",
            database.username, database.password, database.host, database.port,
        );
        log::debug!("bootstrap to {}", url);
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

        let db = Self::new(database).await?;
        db.execute_unprepared("CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\";")
            .await?;
        db.migrate().await?;

        Ok(db)
    }

    pub async fn close(self) -> anyhow::Result<()> {
        Ok(self.db.close().await?)
    }

    /// Ping the database.
    ///
    /// Intended to be used for health checks.
    pub async fn ping(&self) -> anyhow::Result<()> {
        self.db
            .ping()
            .await
            .context("failed to ping the database")?;
        Ok(())
    }
}

impl Deref for Database {
    type Target = DatabaseConnection;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for Database {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

#[crate::db::async_trait::async_trait]
impl ConnectionTrait for Database {
    fn get_database_backend(&self) -> DbBackend {
        self.db.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.db.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.db.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.db.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.db.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.db.support_returning()
    }

    #[cfg(feature = "mock")]
    fn is_mock_connection(&self) -> bool {
        self.db.is_mock_connection()
    }
}

/// A trait to help working with database errors
pub trait DatabaseErrors {
    /// return `true` if the error is a duplicate key error
    fn is_duplicate(&self) -> bool;
}

impl DatabaseErrors for DbErr {
    fn is_duplicate(&self) -> bool {
        match self {
            DbErr::Query(RuntimeErr::SqlxError(sqlx::error::Error::Database(err))) => {
                err.kind() == ErrorKind::UniqueViolation
            }
            _ => false,
        }
    }
}
