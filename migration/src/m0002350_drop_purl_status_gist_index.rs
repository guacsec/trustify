use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop GiST trigram index on purl_status.vulnerability_id introduced
        // in m0000050. The index uses gist_trgm_ops (substring/LIKE matching)
        // but every access in the codebase uses equality (=), which is served
        // by the existing B-tree indexes purl_status_vuln_id_idx and
        // purl_status_combo_idx. The GiST index is never chosen by the
        // query planner (0 scans in production) and wastes ~47 GB of disk.
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name("purl_status_vulnerability_id_gist")
                    .table(PurlStatus::Table)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"CREATE INDEX IF NOT EXISTS purl_status_vulnerability_id_gist
                   ON purl_status
                   USING GIST (vulnerability_id gist_trgm_ops)"#,
            )
            .await
            .map(|_| ())
    }
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
}
