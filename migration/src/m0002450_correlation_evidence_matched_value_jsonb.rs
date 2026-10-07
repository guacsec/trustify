use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // keep existing values, as the identifier without version ranges
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE correlation_evidence
    ALTER COLUMN matched_value TYPE JSONB
    USING CASE WHEN matched_value IS NULL THEN NULL ELSE jsonb_build_object('identifier', matched_value) END
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
ALTER TABLE correlation_evidence
    ALTER COLUMN matched_value TYPE TEXT
    USING matched_value->>'identifier'
"#,
            )
            .await
            .map(|_| ())
    }
}
