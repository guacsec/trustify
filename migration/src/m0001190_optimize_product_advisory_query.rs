use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Index to optimize product_status.package lookups in the optimized query
        // This supports the JOIN in product_status_matches_name CTE
        manager
            .create_index(
                Index::create()
                    .table(ProductStatus::Table)
                    .name(Indexes::ProductStatusPackageIdx.to_string())
                    .col(ProductStatus::Package)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ProductStatus::Table)
                    .name(Indexes::ProductStatusPackageIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Indexes {
    ProductStatusPackageIdx,
}

#[derive(DeriveIden)]
pub enum ProductStatus {
    Table,
    Package,
}
