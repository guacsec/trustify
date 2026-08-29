use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Re-materialize `sbom_describing_cpe` for already-ingested SBOMs under the
        // broadened rule introduced alongside this migration: operating-system CPEs
        // (`part = 'o'`) on ANY node count as product/OS context, not only CPEs on
        // `Describes`-relationship (relationship = 13) nodes.
        //
        // Real RHEL image SBOMs attach the platform CPE (e.g.
        // `cpe:/o:redhat:enterprise_linux:8`) to a child/OS component rather than the
        // Describes node, so the original backfill (m0002110_sbom_describing_cpe) left
        // the table empty for them and the CPE-context filter was disabled via its
        // escape hatch, leaking wrong-product / wrong-scheme matches (TC-5170 /
        // TC-5171). The Describes-node rows are already present from that earlier
        // backfill; this migration only ADDS the OS-CPE rows.
        //
        // Additive and idempotent (`ON CONFLICT DO NOTHING`). Component-identity CPEs
        // (`part = 'a'`, used by cpe_status matching — TC-5630) are intentionally
        // excluded.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                INSERT INTO sbom_describing_cpe (sbom_id, cpe_id)
                SELECT DISTINCT spcr.sbom_id, spcr.cpe_id
                FROM sbom_node_cpe_ref spcr
                JOIN cpe ON cpe.id = spcr.cpe_id
                WHERE cpe.part = 'o'
                ON CONFLICT DO NOTHING
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse only what `up` added: OS-CPE (`part = 'o'`) describing rows that are
        // NOT justified by a `Describes` relationship (relationship = 13). Rows that a
        // Describes node contributes — including OS CPEs on the Describes node itself —
        // are preserved, matching the pre-migration state produced by
        // m0002110_sbom_describing_cpe.
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DELETE FROM sbom_describing_cpe sdc
                USING cpe
                WHERE sdc.cpe_id = cpe.id
                  AND cpe.part = 'o'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM sbom_node_cpe_ref spcr
                      JOIN package_relates_to_package prtp
                        ON prtp.sbom_id = spcr.sbom_id
                       AND (prtp.right_node_id = spcr.node_id OR prtp.left_node_id = spcr.node_id)
                      WHERE spcr.sbom_id = sdc.sbom_id
                        AND spcr.cpe_id = sdc.cpe_id
                        AND prtp.relationship = 13
                  )
                "#,
            )
            .await?;

        Ok(())
    }
}
