use sea_orm_migration::prelude::*;

/// Index describing-package relationships used to infer an SBOM's product supplier.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS prtp_describes_idx \
                 ON package_relates_to_package (sbom_id) \
                 INCLUDE (right_node_id) \
                 WHERE relationship = 13",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS prtp_describes_idx")
            .await?;
        Ok(())
    }
}
