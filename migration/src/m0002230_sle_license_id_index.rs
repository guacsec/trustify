use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The NOT EXISTS subquery in GET /v3/license correlates on
        // sbom_license_expanded.license_id, but the composite PK is
        // (sbom_id, license_id) so license_id-only lookups require a
        // sequential scan. This index enables an index-only anti-join.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS idx_sle_license_id
                ON sbom_license_expanded (license_id)
                "#,
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS idx_sle_license_id")
            .await
            .map(|_| ())?;

        Ok(())
    }
}
