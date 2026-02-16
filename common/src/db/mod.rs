pub mod chunk;
pub mod limiter;
pub mod multi_model;
pub mod query;

mod create;
mod func;

pub use create::*;
pub use func::*;

use anyhow::Context;
use reqwest::Url;
use sea_orm::{
    AccessMode, ConnectOptions, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, ExecResult, IsolationLevel, QueryResult, RuntimeErr, Statement, StreamTrait,
    TransactionError, TransactionTrait, prelude::async_trait,
};
use sea_orm_migration::{IntoSchemaManagerConnection, SchemaManagerConnection};
use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
    pin::Pin,
    time::Duration,
};
use tracing::instrument;

/// A trait to help working with database errors
pub trait DatabaseErrors {
    /// return `true` if the error is a duplicate key error
    fn is_duplicate(&self) -> bool;
    /// return `true` if the error means the connection is read-only
    fn is_read_only(&self) -> bool;
    /// return `true` if the error is a foreign key constraint violation
    fn is_foreign_key_violation(&self) -> bool;
}

impl DatabaseErrors for DbErr {
    fn is_duplicate(&self) -> bool {
        match self {
            DbErr::Query(RuntimeErr::SqlxError(sqlx::error::Error::Database(err)))
            | DbErr::Exec(RuntimeErr::SqlxError(sqlx::error::Error::Database(err))) => {
                err.is_unique_violation()
            }
            _ => false,
        }
    }

    fn is_read_only(&self) -> bool {
        match self {
            DbErr::Query(RuntimeErr::SqlxError(sqlx::error::Error::Database(err)))
            | DbErr::Exec(RuntimeErr::SqlxError(sqlx::error::Error::Database(err))) => {
                err.code().as_deref() == Some("25006")
            }
            _ => false,
        }
    }

    fn is_foreign_key_violation(&self) -> bool {
        match self {
            DbErr::Query(RuntimeErr::SqlxError(sqlx::error::Error::Database(err)))
            | DbErr::Exec(RuntimeErr::SqlxError(sqlx::error::Error::Database(err))) => {
                err.is_foreign_key_violation()
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Database {
    /// the database connection
    db: DatabaseConnection,
    /// the database name
    name: String,
}

impl Database {
    #[instrument(err)]
    pub async fn new(database: &crate::config::Database) -> Result<Self, anyhow::Error> {
        let url = database.to_url();

        if log::log_enabled!(log::Level::Debug) {
            log::debug!("connect to {}", strip_password(url.clone()));
        }

        let mut opt = ConnectOptions::new(url);
        opt.max_connections(database.max_conn);
        opt.min_connections(database.min_conn);
        opt.sqlx_logging_level(log::LevelFilter::Trace);

        opt.connect_timeout(Duration::from_secs(database.connect_timeout));
        opt.acquire_timeout(Duration::from_secs(database.acquire_timeout));
        opt.max_lifetime(Duration::from_secs(database.max_lifetime));
        opt.idle_timeout(Duration::from_secs(database.idle_timeout));

        let db = sea_orm::Database::connect(opt).await?;
        let name = database.name.clone();

        Ok(Self { db, name })
    }

    #[instrument(skip(self), err)]
    pub async fn close(self) -> anyhow::Result<()> {
        Ok(self.db.close().await?)
    }

    /// Ping the database.
    ///
    /// Intended to be used for health checks.
    #[instrument(skip(self), err)]
    pub async fn ping(&self) -> anyhow::Result<()> {
        self.db
            .ping()
            .await
            .context("failed to ping the database")?;
        Ok(())
    }

    /// Get the name of the database
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn into_connection(self) -> DatabaseConnection {
        self.db
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn transaction_with_config<T, E, F>(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
        f: F,
    ) -> Result<T, E>
    where
        F: AsyncFnOnce(&DatabaseTransaction) -> Result<T, E>,
        E: From<DbErr> + Display,
    {
        let tx = self
            .db
            .begin_with_config(isolation_level, access_mode)
            .await?;
        match f(&tx).await {
            // the user function succeeded
            Ok(result) => {
                tx.commit().await?;
                Ok(result)
            }
            // the user function failed
            Err(err) => {
                log::debug!("Function returned with an error: {err}");
                match tx.rollback().await {
                    // we rolled back, but still have the original error to report
                    Ok(_) => Err(err),
                    // we failed rolling back, propagate that state, but log the now omitted,
                    // original error.
                    Err(rollback_err) => {
                        log::warn!("Rollback failed, suppressing original error: {err}");
                        Err(rollback_err.into())
                    }
                }
            }
        }
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: AsyncFnOnce(&DatabaseTransaction) -> Result<T, E>,
        E: From<DbErr> + Display,
    {
        self.transaction_with_config(None, None, f).await
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

/// Implementation of the connection trait for our database struct.
///
/// **NOTE**: We lack the implementations for the `mock` feature. However, the mock feature would
/// require us to have the `Database` struct to be non-clone, which we don't support anyway.
#[async_trait::async_trait]
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
}

#[async_trait::async_trait]
impl TransactionTrait for Database {
    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        self.db.begin().await
    }

    async fn begin_with_config(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<DatabaseTransaction, DbErr> {
        self.db
            .begin_with_config(isolation_level, access_mode)
            .await
    }

    async fn transaction<F, T, E>(&self, callback: F) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        self.db.transaction(callback).await
    }

    async fn transaction_with_config<F, T, E>(
        &self,
        callback: F,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        self.db
            .transaction_with_config(callback, isolation_level, access_mode)
            .await
    }
}

/// Implementation of the connection trait for our database struct.
///
/// **NOTE**: We lack the implementations for the `mock` feature. However, the mock feature would
/// require us to have the `Database` struct to be non-clone, which we don't support anyway.
#[async_trait::async_trait]
impl ConnectionTrait for &Database {
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
}

#[async_trait::async_trait]
impl StreamTrait for Database {
    type Stream<'a> = <DatabaseConnection as StreamTrait>::Stream<'a>;

    fn stream<'a>(
        &'a self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream<'a>, DbErr>> + 'a + Send>> {
        self.db.stream(stmt)
    }
}

#[async_trait::async_trait]
impl<'b> StreamTrait for &'b Database {
    type Stream<'a>
        = <DatabaseConnection as StreamTrait>::Stream<'a>
    where
        'b: 'a;

    fn stream<'a>(
        &'a self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream<'a>, DbErr>> + 'a + Send>> {
        self.db.stream(stmt)
    }
}

impl<'a> IntoSchemaManagerConnection<'a> for &'a Database {
    fn into_schema_manager_connection(self) -> SchemaManagerConnection<'a> {
        self.db.into_schema_manager_connection()
    }
}

/// Remove the password from the URL and replace it with `***`, if present.
///
/// If this is not a URL, or does not contain a password, this is a no-op.
fn strip_password(url: String) -> String {
    match Url::parse(&url) {
        Ok(mut url) => {
            if url.password().is_some() {
                let _ = url.set_password(Some("***"));
            }
            url.to_string()
        }
        Err(_) => url,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// ensure that the password is not present, but not necessarily removing the string itself
    #[test]
    fn url_strip_password() {
        assert_eq!(
            "postgres://trustify:***@infrastructure-postgresql:5432/trustify?sslmode=allow&other=trustify1234",
            strip_password(
                "postgres://trustify:trustify1234@infrastructure-postgresql:5432/trustify?sslmode=allow&other=trustify1234".to_string()
            )
        )
    }

    /// if there's no password, this shouldn't change anything
    #[test]
    fn url_strip_no_password() {
        assert_eq!(
            "postgres://trustify@infrastructure-postgresql:5432/trustify?sslmode=allow&other=trustify1234",
            strip_password(
                "postgres://trustify@infrastructure-postgresql:5432/trustify?sslmode=allow&other=trustify1234".to_string()
            )
        )
    }

    /// if this is not a URL, then it should not panic
    #[test]
    fn url_strip_password_not_a_url() {
        assert_eq!("foo-bar-baz", strip_password("foo-bar-baz".to_string()))
    }
}
