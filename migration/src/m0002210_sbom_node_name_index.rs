use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Covering index to support ORDER BY name with early termination at
        // LIMIT. INCLUDE columns enable the join to sbom without a heap fetch.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS sbom_node_name_covering_idx
                ON sbom_node (name) INCLUDE (sbom_id, node_id)
                "#,
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS sbom_node_name_covering_idx")
            .await
            .map(|_| ())?;

        Ok(())
    }
}
