use sea_orm_migration::prelude::*;

/// Link each PURL assertion to the original identifier stated by its source document.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002600_purl_status_qualified_purl/up.sql"))
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared(include_str!("m0002600_purl_status_qualified_purl/down.sql"))
            .await?;
        connection
            .execute_unprepared(include_str!("m0002590_default_status/up.sql"))
            .await
            .map(|_| ())
    }
}
