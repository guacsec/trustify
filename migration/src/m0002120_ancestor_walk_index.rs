use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop the plain (sbom_id, right_node_id) index from m0002100,
        // superseded by the partial covering index below.
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::PrtpSbomRightNodeIdx.to_string())
                    .to_owned(),
            )
            .await?;

        // Partial covering index for the recursive ancestor walk CTE.
        //
        // The CTE joins on (sbom_id, right_node_id) and filters
        // relationship != 9 (AncestorOf) at every recursion level.
        //
        // This index:
        //  - Pre-filters AncestorOf rows (WHERE relationship != 9)
        //  - Covers the join columns (sbom_id, right_node_id)
        //  - INCLUDEs left_node_id and relationship for index-only scans
        //
        // SeaORM's Index builder doesn't support INCLUDE or WHERE,
        // so this must use raw SQL.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX IF NOT EXISTS prtp_ancestor_walk_idx
                ON package_relates_to_package (sbom_id, right_node_id)
                INCLUDE (left_node_id, relationship)
                WHERE relationship != 9
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::PrtpAncestorWalkIdx.to_string())
                    .to_owned(),
            )
            .await?;

        // Restore the plain index from m0002100 that we dropped in up().
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::PrtpSbomRightNodeIdx.to_string())
                    .col(PackageRelatesToPackage::SbomId)
                    .col(PackageRelatesToPackage::RightNodeId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Indexes {
    PrtpSbomRightNodeIdx,
    PrtpAncestorWalkIdx,
}

#[derive(DeriveIden)]
pub enum PackageRelatesToPackage {
    Table,
    SbomId,
    RightNodeId,
}
