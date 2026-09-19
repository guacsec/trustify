use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Advisory statuses keyed by CPE (vendor/product identity), mirroring
        // purl_status. The referenced CPE carries the affected vendor/product
        // with the version component normalized to ANY; the affected versions
        // are expressed through the version range.
        manager
            .create_table(
                Table::create()
                    .table(CpeStatus::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CpeStatus::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(CpeStatus::AdvisoryId).uuid().not_null())
                    .col(ColumnDef::new(CpeStatus::VulnerabilityId).text().not_null())
                    .col(ColumnDef::new(CpeStatus::StatusId).uuid().not_null())
                    .col(ColumnDef::new(CpeStatus::CpeId).uuid().not_null())
                    .col(ColumnDef::new(CpeStatus::VersionRangeId).uuid().not_null())
                    .col(ColumnDef::new(CpeStatus::ContextCpeId).uuid())
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpeStatus::Table, CpeStatus::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpeStatus::Table, CpeStatus::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpeStatus::Table, CpeStatus::StatusId)
                            .to(Status::Table, Status::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpeStatus::Table, CpeStatus::CpeId)
                            .to(Cpe::Table, Cpe::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpeStatus::Table, CpeStatus::VersionRangeId)
                            .to(VersionRange::Table, VersionRange::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(CpeStatus::Table, CpeStatus::ContextCpeId)
                            .to(Cpe::Table, Cpe::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(CpeStatus::Table)
                    .name("cpe_status_cpe_id_idx")
                    .col(CpeStatus::CpeId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(CpeStatus::Table)
                    .name("cpe_status_advisory_id_vulnerability_id_idx")
                    .col(CpeStatus::AdvisoryId)
                    .col(CpeStatus::VulnerabilityId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().if_exists().table(CpeStatus::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum CpeStatus {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    StatusId,
    CpeId,
    VersionRangeId,
    ContextCpeId,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Id,
}

#[derive(DeriveIden)]
pub enum Vulnerability {
    Table,
    Id,
}

#[derive(DeriveIden)]
pub enum Status {
    Table,
    Id,
}

#[derive(DeriveIden)]
pub enum Cpe {
    Table,
    Id,
}

#[derive(DeriveIden)]
pub enum VersionRange {
    Table,
    Id,
}
