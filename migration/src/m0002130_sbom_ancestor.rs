use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the sbom_ancestor table to materialize cross-SBOM links
        // discovered through shared checksums in sbom_node_checksum.
        manager
            .create_table(
                Table::create()
                    .table(SbomAncestor::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomAncestor::SbomId).uuid().not_null())
                    .col(
                        ColumnDef::new(SbomAncestor::AncestorSbomId)
                            .uuid()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomAncestor::SbomId)
                            .col(SbomAncestor::AncestorSbomId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SbomAncestor::Table, SbomAncestor::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SbomAncestor::Table, SbomAncestor::AncestorSbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Index on ancestor_sbom_id for efficient CASCADE deletes and
        // reverse lookups ("which SBOMs descend from X?").
        manager
            .create_index(
                Index::create()
                    .table(SbomAncestor::Table)
                    .name("idx_sbom_ancestor_ancestor")
                    .col(SbomAncestor::AncestorSbomId)
                    .to_owned(),
            )
            .await?;

        // Backfill from existing data: two SBOMs are linked when they share
        // a node with the same checksum value (RH-specific cross-SBOM linking).
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                INSERT INTO sbom_ancestor (sbom_id, ancestor_sbom_id)
                SELECT DISTINCT snc1.sbom_id, snc2.sbom_id
                FROM sbom_node_checksum snc1
                JOIN sbom_node_checksum snc2
                  ON snc1.value = snc2.value
                WHERE snc1.sbom_id != snc2.sbom_id
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
                    .table(SbomAncestor::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SbomAncestor {
    Table,
    SbomId,
    AncestorSbomId,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}
