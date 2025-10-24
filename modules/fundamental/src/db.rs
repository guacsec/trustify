use crate::error::Error;
use sea_orm::DatabaseTransaction;
use trustify_common::db::Database;

#[async_trait::async_trait]
pub trait DatabaseExt {
    async fn begin_read(&self) -> Result<DatabaseTransaction, Error>;
}

#[async_trait::async_trait]
impl DatabaseExt for Database {
    async fn begin_read(&self) -> Result<DatabaseTransaction, Error> {
        self.begin_read_snapshot().await.map_err(Error::from)
    }
}
