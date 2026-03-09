use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Improve ancestor traversal in find_node_ancestors()
        //
        // find_node_ancestors() is called in an iterative loop, issuing one query per tree level.
        // Each query filters (sbom_id, right_node_id) against a PK ordered (sbom_id, left_node_id, ...).
        // Without this index, every iteration scans all relationships for that SBOM.
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

        // 2. Improve CPE-based component searches
        //
        // CPE-based searches filter by cpe_id without sbom_id. The PK starts with sbom_id,
        // so without this index it requires a full table scan. Covering (cpe_id, sbom_id, node_id)
        // enables index-only scans.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .table(SbomPackageCpeRef::Table)
                    .name(Indexes::SbomPackageCpeRefCpeIdIdx.to_string())
                    .col(SbomPackageCpeRef::CpeId)
                    .col(SbomPackageCpeRef::SbomId)
                    .col(SbomPackageCpeRef::NodeId)
                    .to_owned(),
            )
            .await?;

        // 3. Covering index on sbom for (sbom_id) INCLUDE (published)
        //
        // Enables index-only scans on the sbom join in component name lookups,
        // avoiding heap access for the 'published' column.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                  CREATE INDEX IF NOT EXISTS sbom_covering_published_idx
                  ON sbom (sbom_id) INCLUDE (published)
                  "#,
            )
            .await
            .map(|_| ())?;

        // 4. Covering index on sbom_node for (node_id) INCLUDE (sbom_id, name)
        //
        // Supports ComponentReference::Id lookups and batch node_id IN queries
        // with index-only scans.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                  CREATE INDEX IF NOT EXISTS sbom_node_node_id_covering_idx
                  ON sbom_node (node_id) INCLUDE (sbom_id, name)
                  "#,
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS sbom_node_node_id_covering_idx")
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS sbom_covering_published_idx")
            .await
            .map(|_| ())?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomPackageCpeRef::Table)
                    .name(Indexes::SbomPackageCpeRefCpeIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PackageRelatesToPackage::Table)
                    .name(Indexes::PrtpSbomRightNodeIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Indexes {
    PrtpSbomRightNodeIdx,
    SbomPackageCpeRefCpeIdIdx,
}

#[derive(DeriveIden)]
pub enum PackageRelatesToPackage {
    Table,
    SbomId,
    RightNodeId,
}

#[derive(DeriveIden)]
pub enum SbomPackageCpeRef {
    Table,
    CpeId,
    SbomId,
    NodeId,
}
