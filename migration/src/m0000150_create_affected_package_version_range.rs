use crate::m0000040_create_vulnerability::Vulnerability;
use crate::m0000060_create_advisory::Advisory;
use crate::m0000140_create_package_version_range::PackageVersionRange;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(AffectedPackageVersionRange::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::AdvisoryId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AffectedPackageVersionRange::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::VulnerabilityId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AffectedPackageVersionRange::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::PackageVersionRangeId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AffectedPackageVersionRange::PackageVersionRangeId)
                            .to(PackageVersionRange::Table, PackageVersionRange::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AffectedPackageVersionRange::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum AffectedPackageVersionRange {
    Table,
    Id,
    //Timestamp,
    // --
    AdvisoryId,
    VulnerabilityId,
    PackageVersionRangeId,
}
