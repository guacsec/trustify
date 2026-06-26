pub mod chunk;
pub mod limiter;
pub mod multi_model;
pub mod pagination_cache;
pub mod query;

mod create;
mod func;

pub use create::*;
pub use func::*;

use actix_web::{HttpResponse, ResponseError};
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
    str::FromStr,
    time::Duration,
};
use tracing::instrument;

/// Begin a REPEATABLE READ transaction for consistent read operations.
///
/// This ensures that all queries within the transaction see a consistent snapshot
/// of the database, preventing race conditions from concurrent write operations, e.g. DELETE
///
/// Uses REPEATABLE READ isolation level with READ ONLY access mode, which is
/// lightweight in PostgreSQL (no locks acquired, uses MVCC snapshots).
#[async_trait::async_trait]
pub trait DatabaseExt {
    async fn begin_read(&self) -> Result<DatabaseTransaction, DbErr>;
}

#[async_trait::async_trait]
impl<T> DatabaseExt for T
where
    T: TransactionTrait + Sync,
{
    async fn begin_read(&self) -> Result<DatabaseTransaction, DbErr> {
        self.begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await
    }
}

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
    #[instrument(skip(database), fields(database = ?crate::redact::HideString(database, &database.password.0)), err(level=tracing::Level::INFO))]
    pub async fn new(database: &crate::config::Database) -> Result<Self, anyhow::Error> {
        let url = database.to_url();

        if log::log_enabled!(log::Level::Debug) {
            log::debug!("connect to {}", strip_password(url.clone()));
        }

        let mut opt = ConnectOptions::new(url);
        opt.max_connections(database.max_conn);
        opt.min_connections(database.min_conn);

        opt.sqlx_logging_level(log::LevelFilter::Trace);
        if let Some(threshold) = std::env::var("TRUSTD_SLOW_SQL_THRESHOLD")
            .ok()
            .and_then(|s| humantime::Duration::from_str(&s).ok())
        {
            opt.sqlx_logging(true);
            opt.sqlx_slow_statements_logging_settings(log::LevelFilter::Warn, *threshold);
        }

        opt.connect_timeout(Duration::from_secs(database.connect_timeout));
        opt.acquire_timeout(Duration::from_secs(database.acquire_timeout));
        opt.max_lifetime(Duration::from_secs(database.max_lifetime));
        opt.idle_timeout(Duration::from_secs(database.idle_timeout));

        let db = sea_orm::Database::connect(opt).await?;
        let name = database.name.clone();

        Ok(Self { db, name })
    }

    #[instrument(skip(self), err(level=tracing::Level::INFO))]
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

/// Read-write database connection wrapper.
///
/// Provides full database access including read-write transactions.
/// Used by endpoints and services that perform mutations (ingestion, imports, deletes).
#[derive(Clone, Debug)]
pub struct ReadWrite(Database);

impl ReadWrite {
    /// Wraps an existing database connection for read-write access.
    pub fn new(db: Database) -> Self {
        Self(db)
    }

    /// Close the connection.
    pub async fn close(self) -> anyhow::Result<()> {
        self.0.close().await
    }

    /// Runs a closure inside a transaction, committing on success and rolling back on error.
    pub async fn transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: AsyncFnOnce(&DatabaseTransaction) -> Result<T, E>,
        E: From<DbErr> + Display,
    {
        self.0.transaction(f).await
    }

    /// Runs a closure inside a transaction with the given isolation level and access mode.
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
        self.0
            .transaction_with_config(isolation_level, access_mode, f)
            .await
    }

    /// Extracts the inner Database, consuming this wrapper.
    pub fn into_inner(self) -> Database {
        self.0
    }
}

impl Deref for ReadWrite {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for ReadWrite {
    fn get_database_backend(&self) -> DbBackend {
        self.0.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.0.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.0.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.0.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.0.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.0.support_returning()
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for &ReadWrite {
    fn get_database_backend(&self) -> DbBackend {
        self.0.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.0.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.0.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.0.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.0.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.0.support_returning()
    }
}

#[async_trait::async_trait]
impl StreamTrait for ReadWrite {
    type Stream<'a> = <DatabaseConnection as StreamTrait>::Stream<'a>;

    fn stream<'a>(
        &'a self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream<'a>, DbErr>> + 'a + Send>> {
        self.0.stream(stmt)
    }
}

#[async_trait::async_trait]
impl<'b> StreamTrait for &'b ReadWrite {
    type Stream<'a>
        = <DatabaseConnection as StreamTrait>::Stream<'a>
    where
        'b: 'a;

    fn stream<'a>(
        &'a self,
        stmt: Statement,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Stream<'a>, DbErr>> + 'a + Send>> {
        self.0.stream(stmt)
    }
}

impl<'a> IntoSchemaManagerConnection<'a> for &'a ReadWrite {
    fn into_schema_manager_connection(self) -> SchemaManagerConnection<'a> {
        (&self.0).into_schema_manager_connection()
    }
}

#[async_trait::async_trait]
impl TransactionTrait for ReadWrite {
    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        self.0.begin().await
    }

    async fn begin_with_config(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<DatabaseTransaction, DbErr> {
        self.0.begin_with_config(isolation_level, access_mode).await
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
        TransactionTrait::transaction(&self.0, callback).await
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
        TransactionTrait::transaction_with_config(&self.0, callback, isolation_level, access_mode)
            .await
    }
}

/// Error returned by `ReadOnly::begin()`, compatible with both actix handlers and module error types.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Database(DbErr),
    #[error("unavailable")]
    Unavailable,
    #[error("cannot open a read-write transaction on a read-only connection")]
    ReadOnly,
}

impl From<DbErr> for DbError {
    fn from(err: DbErr) -> Self {
        if err.is_read_only() {
            Self::Unavailable
        } else {
            Self::Database(err)
        }
    }
}

impl ResponseError for DbError {
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::Unavailable => HttpResponse::ServiceUnavailable()
                .json(crate::error::ErrorInformation::new("Unavailable", self)),
            Self::ReadOnly => HttpResponse::Forbidden()
                .json(crate::error::ErrorInformation::new("ReadOnly", self)),
            Self::Database(err) => {
                log::warn!("{err}");
                HttpResponse::InternalServerError()
                    .json(crate::error::ErrorInformation::new("Database", ""))
            }
        }
    }
}

/// Read-only database connection factory.
///
/// Does not implement `ConnectionTrait` directly — callers must use `begin()` to obtain
/// a `DatabaseTransaction` opened with `AccessMode::ReadOnly`. All operations then go
/// through that transaction, which PostgreSQL enforces as read-only.
#[derive(Clone, Debug)]
pub struct ReadOnly(Database);

impl ReadOnly {
    /// Wraps an existing database connection for read-only access.
    pub fn new(db: Database) -> Self {
        Self(db)
    }

    /// Get the name of the database.
    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// Ping the database for health checks.
    pub async fn ping(&self) -> anyhow::Result<()> {
        self.0.ping().await
    }

    /// Close the connection.
    pub async fn close(self) -> anyhow::Result<()> {
        self.0.close().await
    }

    /// Begins a read-only transaction.
    pub async fn begin(&self) -> Result<DatabaseTransaction, DbError> {
        Ok(self
            .0
            .begin_with_config(None, Some(AccessMode::ReadOnly))
            .await?)
    }

    /// Begins a read-only transaction with the given isolation level.
    ///
    /// The access mode is always forced to `ReadOnly`; passing `ReadWrite` returns an error.
    pub async fn begin_with_config(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<DatabaseTransaction, DbError> {
        let mode = Self::validate_access_mode(access_mode)?;
        Ok(self.0.begin_with_config(isolation_level, mode).await?)
    }

    /// Validates the access mode, rejecting explicit read-write requests.
    fn validate_access_mode(mode: Option<AccessMode>) -> Result<Option<AccessMode>, DbError> {
        match mode {
            Some(AccessMode::ReadWrite) => Err(DbError::ReadOnly),
            _ => Ok(Some(AccessMode::ReadOnly)),
        }
    }

    /// Extracts the inner Database, consuming this wrapper.
    pub fn into_inner(self) -> Database {
        self.0
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

    #[test]
    fn read_only_rejects_explicit_read_write_mode() {
        let result = ReadOnly::validate_access_mode(Some(AccessMode::ReadWrite));
        assert!(
            matches!(result, Err(DbError::ReadOnly)),
            "explicit ReadWrite must be rejected"
        );
    }

    #[test]
    fn read_only_allows_none_and_read_only_mode() {
        let result = ReadOnly::validate_access_mode(None);
        assert_eq!(result.unwrap(), Some(AccessMode::ReadOnly));

        let result = ReadOnly::validate_access_mode(Some(AccessMode::ReadOnly));
        assert_eq!(result.unwrap(), Some(AccessMode::ReadOnly));
    }
}
