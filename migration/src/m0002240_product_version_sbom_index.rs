use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(ProductVersion::Table)
                    .name("product_version_sbom_id_idx")
                    .col(ProductVersion::SbomId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ProductVersion::Table)
                    .name("product_version_sbom_id_idx")
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ProductVersion {
    Table,
    SbomId,
}
