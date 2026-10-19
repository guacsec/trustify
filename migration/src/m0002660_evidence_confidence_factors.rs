use sea_orm_migration::prelude::*;

/// The factors of the confidence of a piece of evidence, to explain how it comes about.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE correlation_evidence
    ADD COLUMN IF NOT EXISTS confidence_factors jsonb NOT NULL DEFAULT '[]';
"#,
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE correlation_evidence DROP COLUMN IF EXISTS confidence_factors;
"#,
            )
            .await
            .map(|_| ())
    }
}
