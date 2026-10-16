use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE correlation_weight_policy")
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Policy values have been discarded; rollback restores only the schema.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE correlation_weight_policy (
                id uuid PRIMARY KEY, revision uuid NOT NULL,
                scope jsonb NOT NULL UNIQUE, priority integer NOT NULL DEFAULT 0,
                weights jsonb NOT NULL
            )",
            )
            .await
            .map(|_| ())
    }
}
