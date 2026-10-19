use sea_orm_migration::prelude::*;

/// The version range of the product a product identifier assertion identifies, e.g. the firmware
/// versions a model number is stated for.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE advisory_vulnerability_product_identifier
    ADD COLUMN IF NOT EXISTS version_range_id uuid REFERENCES version_range(id);
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
ALTER TABLE advisory_vulnerability_product_identifier DROP COLUMN IF EXISTS version_range_id;
"#,
            )
            .await
            .map(|_| ())
    }
}
