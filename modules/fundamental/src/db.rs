use crate::error::Error;
use sea_orm::{AccessMode, DatabaseTransaction, IsolationLevel, TransactionTrait};

#[async_trait::async_trait]
pub trait DatabaseExt {
    /// Begin a REPEATABLE READ transaction for consistent read operations.
    ///
    /// This ensures that all queries within the transaction see a consistent snapshot
    /// of the database, preventing race conditions from concurrent write operations, e.g. DELETE
    ///
    /// Uses REPEATABLE READ isolation level with READ ONLY access mode, which is
    /// lightweight in PostgreSQL (no locks acquired, uses MVCC snapshots).
    async fn begin_read(&self) -> Result<DatabaseTransaction, Error>;
}

#[async_trait::async_trait]
impl<T> DatabaseExt for T
where
    T: TransactionTrait + Sync,
{
    async fn begin_read(&self) -> Result<DatabaseTransaction, Error> {
        self.begin_with_config(
            Some(IsolationLevel::RepeatableRead),
            Some(AccessMode::ReadOnly),
        )
        .await
        .map_err(Error::from)
    }
}
