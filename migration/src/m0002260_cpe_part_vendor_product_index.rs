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
                    .table(Cpe::Table)
                    .name("cpe_part_vendor_product_idx")
                    .col(Cpe::Part)
                    .col(Cpe::Vendor)
                    .col(Cpe::Product)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Cpe::Table)
                    .name("cpe_part_vendor_product_idx")
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Cpe {
    Table,
    Part,
    Vendor,
    Product,
}
