use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        // PostgreSQL cannot build or drop indexes concurrently inside a transaction.
        Some(false)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SBOM backlink CPE generalization looks up vendor/product/version without a part.
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS cpe_vendor_product_version_idx \
                 ON cpe (vendor, product, version) INCLUDE (id)",
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX CONCURRENTLY IF EXISTS cpe_vendor_product_version_idx")
            .await
            .map(|_| ())
    }
}
