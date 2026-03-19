use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::IdxPackageRelatesToPackageRightId.to_string())
                    .col(PackageRelatesToPackage::SbomId)
                    .col(PackageRelatesToPackage::Relationship)
                    .col(PackageRelatesToPackage::RightNodeId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop indexes in reverse order
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::IdxPackageRelatesToPackageRightId.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Indexes {
    IdxPackageRelatesToPackageRightId,
}

#[derive(DeriveIden)]
enum PackageRelatesToPackage {
    Table,
    SbomId,
    Relationship,
    RightNodeId,
}
