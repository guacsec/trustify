pub mod change;
pub mod chunk;
pub mod limiter;
pub mod multi_model;
pub mod pagination_cache;
pub mod query;
pub mod rds_iam;

mod create;
mod func;

pub use create::*;
pub use func::*;

use crate::config::Database as DatabaseConfig;

use actix_web::{HttpResponse, ResponseError};
use anyhow::Context;
use url::Url;
use sea_orm::{
    AccessMode, ConnectOptions, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, ExecResult, IsolationLevel, QueryResult, RuntimeErr, SqlxPostgresConnector,
    Statement, StreamTrait, TransactionError, TransactionTrait, prelude::async_trait,
};
use sea_orm_migration::{IntoSchemaManagerConnection, SchemaManagerConnection};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};
use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{spawn, sync::oneshot, time};
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
    /// Keeps the RDS IAM token refresher task alive for exactly as long as any `Database`
    /// clone lives. Non-IAM connections have no refresher, so this is `None` for them. When
    /// the last clone is dropped, this shutdown sender is dropped, closing the oneshot channel
    /// the task selects on; the task then exits, drops its `PgPool` clone, and lets the pool
    /// (and its connections) be released.
    _iam_refresher: Option<Arc<oneshot::Sender<()>>>,
}

impl Database {
    #[instrument(skip(database), fields(database = ?crate::redact::HideString(database, &database.password.0)), err(level=tracing::Level::INFO))]
    pub async fn new(database: &DatabaseConfig) -> Result<Self, anyhow::Error> {
        // RDS/Aurora IAM authentication uses a short-lived, auto-refreshed token as the
        // password and requires a dedicated, self-refreshing connection pool.
        if database.iam_auth {
            return Self::new_with_iam_auth(database).await;
        }

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

        Ok(Self {
            db,
            name,
            _iam_refresher: None,
        })
    }

    /// Connect using AWS RDS/Aurora IAM authentication.
    ///
    /// Unlike [`Self::new`], the password is a short-lived IAM token rather than a static
    /// secret. Because tokens expire (see [`rds_iam::RDS_IAM_TOKEN_EXPIRY`]) but a
    /// connection pool opens new physical connections over its lifetime, this builds the
    /// pool directly with `sqlx` and spawns a background task that regenerates the token
    /// and swaps it into the pool via [`sqlx::Pool::set_connect_options`]. Every *new*
    /// connection then authenticates with a fresh token; already-open connections keep
    /// working past expiry.
    #[instrument(skip(database), fields(host = database.host, name = database.name), err(level=tracing::Level::INFO))]
    async fn new_with_iam_auth(database: &DatabaseConfig) -> Result<Self, anyhow::Error> {
        anyhow::ensure!(
            database.url.is_none(),
            "'--db-url' cannot be combined with IAM authentication"
        );
        let (region, ssl_mode) = iam_auth_params(database)?;

        log::info!(
            "connecting to {}:{} db '{}' as '{}' using RDS IAM authentication (region: {region}, sslmode: {ssl_mode:?})",
            database.host,
            database.port,
            database.name,
            database.username,
        );

        let token = rds_iam::generate_rds_iam_token(
            &database.host,
            database.port,
            &database.username,
            &region,
        )
        .await
        .context("failed to generate initial RDS IAM auth token")?;

        let pool = PgPoolOptions::new()
            .max_connections(database.max_conn)
            .min_connections(database.min_conn)
            .acquire_timeout(Duration::from_secs(database.acquire_timeout))
            .max_lifetime(Duration::from_secs(database.max_lifetime))
            .idle_timeout(Duration::from_secs(database.idle_timeout))
            .connect_with(pg_connect_options(database, ssl_mode, &token))
            .await
            .context("failed to connect to database using RDS IAM authentication")?;

        let shutdown = spawn_iam_token_refresher(pool.clone(), database.clone(), region, ssl_mode);

        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        let name = database.name.clone();

        Ok(Self {
            db,
            name,
            _iam_refresher: Some(Arc::new(shutdown)),
        })
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
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn begin(&self) -> Result<DatabaseTransaction, DbError> {
        Ok(self
            .0
            .begin_with_config(None, Some(AccessMode::ReadOnly))
            .await?)
    }

    /// Begins a read-only transaction with the given isolation level.
    ///
    /// The access mode is always forced to `ReadOnly`; passing `ReadWrite` returns an error.
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
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

/// Map trustify's [`crate::config::SslMode`] to sqlx's [`PgSslMode`].
impl From<crate::config::SslMode> for PgSslMode {
    fn from(mode: crate::config::SslMode) -> Self {
        use crate::config::SslMode;
        match mode {
            SslMode::Disable => PgSslMode::Disable,
            SslMode::Allow => PgSslMode::Allow,
            SslMode::Prefer => PgSslMode::Prefer,
            SslMode::Require => PgSslMode::Require,
            SslMode::VerifyCa => PgSslMode::VerifyCa,
            SslMode::VerifyFull => PgSslMode::VerifyFull,
        }
    }
}

/// Ensure the SSL mode enforces encryption, as required by RDS IAM authentication.
///
/// Modes weaker than `Require` (which permit an unencrypted connection) are rejected so the
/// misconfiguration surfaces explicitly, rather than being silently overridden; `Require` and
/// the stricter modes (`VerifyCa`, `VerifyFull`) are accepted as configured.
fn require_tls(mode: PgSslMode) -> Result<PgSslMode, anyhow::Error> {
    match mode {
        PgSslMode::Disable | PgSslMode::Allow | PgSslMode::Prefer => Err(anyhow::anyhow!(
            "RDS IAM authentication mandates TLS, but sslmode is set to {mode:?}; \
             set '--db-sslmode' (TRUSTD_DB_SSLMODE) to 'require', 'verify-ca', or 'verify-full'"
        )),
        strict => Ok(strict),
    }
}

/// Validate the prerequisites shared by every RDS IAM-authenticated connection and return
/// the resolved region together with the TLS-enforced SSL mode.
///
/// Fails fast with a clear message when the region is missing or no AWS credentials are
/// configured, instead of attempting an AWS-authenticated connection that cannot succeed.
fn iam_auth_params(
    database: &DatabaseConfig,
) -> Result<(String, PgSslMode), anyhow::Error> {
    let region = database.region.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "'--db-region' (TRUSTD_DB_REGION) is required when IAM authentication is enabled"
        )
    })?;

    // RDS IAM tokens are signed with AWS credentials from the default provider chain. If
    // nothing in the environment points at a credential source, fail fast.
    anyhow::ensure!(
        crate::aws::aws_credentials_configured(),
        "RDS IAM authentication is enabled but no AWS credentials are configured; \
         set AWS credentials (e.g. AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE, or \
         AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY), or set TRUSTD_AWS_USE_IMDS=true \
         on an EC2 deployment using an instance-profile role"
    );

    // RDS IAM authentication mandates TLS; reject anything weaker than `Require`.
    Ok((region, require_tls(database.sslmode.into())?))
}

/// Establish a single, short-lived administrative connection to the database named in
/// `database`.
///
/// Bootstrap/setup connect to the `postgres` maintenance database to create (or drop) the
/// target database. When RDS IAM authentication is enabled the static password is absent or
/// invalid, so this generates a one-off IAM token (with TLS forced on, as IAM mandates)
/// rather than relying on [`crate::config::Database::to_url`]'s static password. Unlike
/// [`Database::new`] no token refresher is spawned: the connection is used once, well within
/// a single token's lifetime, and then closed.
#[instrument(skip(database), fields(host = database.host, name = database.name), err(level=tracing::Level::INFO))]
pub async fn connect_admin(
    database: &DatabaseConfig,
) -> Result<DatabaseConnection, anyhow::Error> {
    if !database.iam_auth {
        let url = database.to_url();
        if log::log_enabled!(log::Level::Debug) {
            log::debug!("connect (admin) to {}", strip_password(url.clone()));
        }
        return Ok(sea_orm::Database::connect(url).await?);
    }

    let (region, ssl_mode) = iam_auth_params(database)?;

    log::info!(
        "connecting to {}:{} db '{}' as '{}' using RDS IAM authentication (admin, region: {region}, sslmode: {ssl_mode:?})",
        database.host,
        database.port,
        database.name,
        database.username,
    );

    let token =
        rds_iam::generate_rds_iam_token(&database.host, database.port, &database.username, &region)
            .await
            .context("failed to generate RDS IAM auth token for administrative connection")?;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pg_connect_options(database, ssl_mode, &token))
        .await
        .context("failed to connect to database using RDS IAM authentication (admin)")?;

    Ok(SqlxPostgresConnector::from_sqlx_postgres_pool(pool))
}

/// Build the postgres connect options for an IAM-authenticated connection, using the
/// given short-lived IAM token as the password.
fn pg_connect_options(
    database: &DatabaseConfig,
    ssl_mode: PgSslMode,
    token: &str,
) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(&database.host)
        .port(database.port)
        .username(&database.username)
        .password(token)
        .database(&database.name)
        .ssl_mode(ssl_mode)
}

/// Spawn a background task that keeps a pool's RDS IAM token fresh.
///
/// Every [`rds_iam::RDS_IAM_TOKEN_REFRESH`] it regenerates the token and swaps it into the
/// pool so subsequent new connections authenticate with a valid token. A failed refresh is
/// logged and retried on the next tick — existing connections and the current (not-yet-expired)
/// token remain usable in the meantime.
///
/// The task exits when the pool is explicitly closed (`is_closed()`), or when the returned
/// shutdown sender is dropped. The caller ([`Database`]) holds that sender so the task is
/// signalled to stop once the last `Database` clone is dropped; this is required because the
/// task owns a strong `PgPool` clone and a merely-dropped (never-closed) pool never reports
/// `is_closed()`, which would otherwise leak the task and its connections.
fn spawn_iam_token_refresher(
    pool: PgPool,
    database: DatabaseConfig,
    region: String,
    ssl_mode: PgSslMode,
) -> oneshot::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    spawn(async move {
        loop {
            tokio::select! {
                _ = time::sleep(rds_iam::RDS_IAM_TOKEN_REFRESH) => {}
                // The sender is dropped (channel closed) when the last `Database` clone is
                // dropped; stop refreshing so the task and its pool clone are released.
                _ = &mut shutdown_rx => {
                    log::debug!("Database dropped; stopping RDS IAM token refresher");
                    break;
                }
            }

            if pool.is_closed() {
                log::debug!("database pool closed; stopping RDS IAM token refresher");
                break;
            }

            match rds_iam::generate_rds_iam_token(
                &database.host,
                database.port,
                &database.username,
                &region,
            )
            .await
            {
                Ok(token) => {
                    pool.set_connect_options(pg_connect_options(&database, ssl_mode, &token));
                    log::debug!("refreshed RDS IAM auth token for new database connections");
                }
                Err(err) => {
                    log::error!("failed to refresh RDS IAM auth token: {err:#}");
                }
            }
        }
    });
    shutdown_tx
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

    #[test]
    fn require_tls_rejects_modes_weaker_than_require() {
        for mode in [PgSslMode::Disable, PgSslMode::Allow, PgSslMode::Prefer] {
            assert!(
                require_tls(mode).is_err(),
                "sslmode {mode:?} must be rejected under RDS IAM authentication"
            );
        }
    }

    #[test]
    fn require_tls_accepts_require_and_stricter_modes() {
        for mode in [
            PgSslMode::Require,
            PgSslMode::VerifyCa,
            PgSslMode::VerifyFull,
        ] {
            // `PgSslMode` implements neither `PartialEq` nor `Clone`, so compare via `Debug`.
            let expected = format!("{mode:?}");
            assert_eq!(format!("{:?}", require_tls(mode).unwrap()), expected);
        }
    }
}
