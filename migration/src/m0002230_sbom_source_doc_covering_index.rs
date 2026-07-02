use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop the plain index on source_document_id — it is subsumed by the
        // covering index below (same leading column, plus INCLUDE payload).
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS sbom_source_document_id_idx")
            .await
            .map(|_| ())?;

        // Covering index lets the planner drive from source_document (sorted by
        // ingested DESC) into sbom via source_document_id, then join sbom_node
        // using the INCLUDEd columns — avoiding a full sort for
        // ORDER BY ingested DESC LIMIT N queries.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS sbom_source_doc_id_covering_idx
                ON sbom (source_document_id)
                INCLUDE (sbom_id, node_id)
                "#,
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS sbom_source_doc_id_covering_idx")
            .await
            .map(|_| ())?;

        // Restore the original plain index.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS sbom_source_document_id_idx ON sbom (source_document_id)",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }
}
