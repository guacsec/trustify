use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Supports global ORDER BY name with early termination at LIMIT.
        manager
            .get_connection()
            .execute_unprepared("CREATE INDEX IF NOT EXISTS base_purl_name_idx ON base_purl (name)")
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS base_purl_name_idx")
            .await
            .map(|_| ())
    }
}
