use sea_orm_migration::{
    prelude::{extension::postgres::Type, *},
    sea_orm::{EnumIter, Iterable},
};

use crate::UuidV4;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_type(
                Type::create()
                    .as_enum(RemediationCategory::Type)
                    .values([
                        RemediationCategory::VendorFix,
                        RemediationCategory::Workaround,
                        RemediationCategory::Mitigation,
                        RemediationCategory::NoFixPlanned,
                        RemediationCategory::NoneAvailable,
                        RemediationCategory::WillNotFix,
                    ])
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Remediation::Table)
                    .col(
                        ColumnDef::new(Remediation::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4)),
                    )
                    .col(ColumnDef::new(Remediation::AdvisoryId).uuid().not_null())
                    .col(
                        ColumnDef::new(Remediation::VulnerabilityId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Remediation::Category)
                            .enumeration(RemediationCategory::Type, RemediationCategory::iter())
                            .not_null(),
                    )
                    .col(ColumnDef::new(Remediation::Details).string())
                    .col(ColumnDef::new(Remediation::Url).string())
                    .col(ColumnDef::new(Remediation::Data).json_binary())
                    .primary_key(Index::create().col(Remediation::Id).primary())
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                Remediation::Table,
                                (Remediation::AdvisoryId, Remediation::VulnerabilityId),
                            )
                            .to(
                                AdvisoryVulnerability::Table,
                                (
                                    AdvisoryVulnerability::AdvisoryId,
                                    AdvisoryVulnerability::VulnerabilityId,
                                ),
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Remediation::Table)
                    .name("idx_remediation_advisory_vuln")
                    .col(Remediation::AdvisoryId)
                    .col(Remediation::VulnerabilityId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(RemediationPurlStatus::Table)
                    .col(ColumnDef::new(RemediationPurlStatus::RemediationId).uuid())
                    .col(ColumnDef::new(RemediationPurlStatus::PurlStatusId).uuid())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RemediationPurlStatus::RemediationId)
                            .to(Remediation::Table, Remediation::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RemediationPurlStatus::PurlStatusId)
                            .to(PurlStatus::Table, PurlStatus::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(RemediationPurlStatus::RemediationId)
                            .col(RemediationPurlStatus::PurlStatusId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(RemediationPurlStatus::Table)
                    .name("idx_remediation_purl_status_purl")
                    .col(RemediationPurlStatus::PurlStatusId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(RemediationProductStatus::Table)
                    .col(ColumnDef::new(RemediationProductStatus::RemediationId).uuid())
                    .col(ColumnDef::new(RemediationProductStatus::ProductStatusId).uuid())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RemediationProductStatus::RemediationId)
                            .to(Remediation::Table, Remediation::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(RemediationProductStatus::ProductStatusId)
                            .to(ProductStatus::Table, ProductStatus::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(RemediationProductStatus::RemediationId)
                            .col(RemediationProductStatus::ProductStatusId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(RemediationProductStatus::Table)
                    .name("idx_remediation_product_status_product")
                    .col(RemediationProductStatus::ProductStatusId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RemediationPurlStatus::Table).to_owned())
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(RemediationProductStatus::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(Remediation::Table).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(RemediationCategory::Type).to_owned())
            .await
    }
}

#[derive(EnumIter)]
enum RemediationCategory {
    Type,
    VendorFix,
    Workaround,
    Mitigation,
    NoFixPlanned,
    NoneAvailable,
    WillNotFix,
}

impl Iden for RemediationCategory {
    fn unquoted(&self, s: &mut dyn Write) {
        #[allow(clippy::unwrap_used)]
        write!(
            s,
            "{}",
            match self {
                Self::Type => "remediation_category",
                Self::VendorFix => "vendor_fix",
                Self::Workaround => "workaround",
                Self::Mitigation => "mitigation",
                Self::NoFixPlanned => "no_fix_planned",
                Self::NoneAvailable => "none_available",
                Self::WillNotFix => "will_not_fix",
            }
        )
        .unwrap();
    }
}

#[derive(DeriveIden)]
enum Remediation {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    Category,
    Details,
    Url,
    Data,
}

#[derive(DeriveIden)]
enum RemediationPurlStatus {
    Table,
    RemediationId,
    PurlStatusId,
}

#[derive(DeriveIden)]
enum RemediationProductStatus {
    Table,
    RemediationId,
    ProductStatusId,
}

#[derive(DeriveIden)]
enum AdvisoryVulnerability {
    Table,
    AdvisoryId,
    VulnerabilityId,
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProductStatus {
    Table,
    Id,
}
