use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await
            .map(|_| ())
    }
}
