use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Partial covering index for the recursive ancestor walk CTE.
        //
        // The CTE joins on (sbom_id, right_node_id) and filters
        // relationship != 9 (AncestorOf) at every recursion level.
        // The existing index on (sbom_id, right_node_id) requires a
        // heap lookup for left_node_id and relationship on each hit.
        //
        // This index:
        //  - Pre-filters AncestorOf rows (WHERE relationship != 9)
        //  - Covers the join columns (sbom_id, right_node_id)
        //  - INCLUDEs left_node_id and relationship for index-only scans
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS prtp_ancestor_walk_idx
                ON package_relates_to_package (sbom_id, right_node_id)
                INCLUDE (left_node_id, relationship)
                WHERE relationship != 9
                "#,
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS prtp_ancestor_walk_idx")
            .await
            .map(|_| ())?;

        Ok(())
    }
}
