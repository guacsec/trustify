use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the sbom_describing_cpe table to materialize the CPEs associated
        // with packages that describe each SBOM, avoiding repeated joins at query time.
        manager
            .create_table(
                Table::create()
                    .table(SbomDescribingCpe::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomDescribingCpe::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomDescribingCpe::CpeId).uuid().not_null())
                    .primary_key(
                        Index::create()
                            .col(SbomDescribingCpe::SbomId)
                            .col(SbomDescribingCpe::CpeId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SbomDescribingCpe::Table, SbomDescribingCpe::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SbomDescribingCpe::Table, SbomDescribingCpe::CpeId)
                            .to(Cpe::Table, Cpe::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Backfill from existing data: find CPEs on nodes involved in Describes relationships.
        // The OR covers both patterns (CPE on right_node_id for SPDX/CycloneDX,
        // and CPE on left_node_id for the ingest_describes_cpe22 helper).
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                INSERT INTO sbom_describing_cpe (sbom_id, cpe_id)
                SELECT DISTINCT spcr.sbom_id, spcr.cpe_id
                FROM sbom_node_cpe_ref spcr
                JOIN package_relates_to_package prtp
                  ON prtp.sbom_id = spcr.sbom_id
                 AND (prtp.right_node_id = spcr.node_id OR prtp.left_node_id = spcr.node_id)
                WHERE prtp.relationship = 13
                ON CONFLICT DO NOTHING
                "#,
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(SbomDescribingCpe::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SbomDescribingCpe {
    Table,
    SbomId,
    CpeId,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
pub enum Cpe {
    Table,
    Id,
}
