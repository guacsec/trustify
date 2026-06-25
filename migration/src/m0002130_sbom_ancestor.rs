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

        // Composite index on (value, sbom_id) for efficient lookups when
        // finding SBOMs that share a given checksum value.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS sbom_node_checksum_value_sbom_id_idx
                ON sbom_node_checksum (value, sbom_id)
                "#,
            )
            .await?;

        // Backfill from existing data, scoped to actual external node references.
        // The SBOM with the external_node_ref is the ancestor (product);
        // the checksum-matched SBOM is the child (component).
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                INSERT INTO sbom_ancestor (sbom_id, ancestor_sbom_id)
                SELECT DISTINCT snc_other.sbom_id, sen.sbom_id
                FROM sbom_external_node sen
                JOIN sbom_node_checksum snc_ref
                  ON snc_ref.sbom_id = sen.sbom_id
                 AND snc_ref.node_id = sen.external_node_ref
                JOIN sbom_node_checksum snc_other
                  ON snc_other.value = snc_ref.value
                 AND snc_other.sbom_id != sen.sbom_id
                ON CONFLICT DO NOTHING
                "#,
            )
            .await?;

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

        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS sbom_node_checksum_value_sbom_id_idx")
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
