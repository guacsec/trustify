use sea_orm_migration::prelude::*;

/// Allow several evidence records of one extractor for the same node and vulnerability, one per
/// status (e.g. a versionless statement being `affected` for one product and `not_affected` for
/// another).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TABLE correlation_evidence
    DROP CONSTRAINT IF EXISTS correlation_evidence_sbom_id_node_id_advisory_id_vulnerabil_key;

ALTER TABLE correlation_evidence
    DROP CONSTRAINT IF EXISTS correlation_evidence_key;

ALTER TABLE correlation_evidence
    ADD CONSTRAINT correlation_evidence_key
    UNIQUE (sbom_id, node_id, advisory_id, vulnerability_id, extractor, status);
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
ALTER TABLE correlation_evidence
    DROP CONSTRAINT IF EXISTS correlation_evidence_key;

-- keep one status per extractor, as the previous constraint requires
DELETE FROM correlation_evidence a
    USING correlation_evidence b
    WHERE a.sbom_id = b.sbom_id
      AND a.node_id = b.node_id
      AND a.advisory_id = b.advisory_id
      AND a.vulnerability_id = b.vulnerability_id
      AND a.extractor = b.extractor
      AND a.id > b.id;

ALTER TABLE correlation_evidence
    ADD CONSTRAINT correlation_evidence_sbom_id_node_id_advisory_id_vulnerabil_key
    UNIQUE (sbom_id, node_id, advisory_id, vulnerability_id, extractor);
"#,
            )
            .await
            .map(|_| ())
    }
}
