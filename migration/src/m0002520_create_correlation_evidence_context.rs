use sea_orm_migration::prelude::*;

/// Links correlation evidence with the assertion contexts (products) it was matched in, and
/// records how the SBOM node got into that product, which determines the confidence.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
DO $$ BEGIN
    CREATE TYPE correlation_context_source AS ENUM (
        'node', 'ancestor_node', 'describing', 'ancestor_sbom',
        'purl_qualifier', 'purl_release', 'unconfirmed'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS correlation_evidence_context (
    evidence_id        UUID NOT NULL REFERENCES correlation_evidence(id) ON DELETE CASCADE,
    context_id         UUID NOT NULL REFERENCES assertion_context(id),
    source             correlation_context_source NOT NULL,
    distance           INTEGER NOT NULL,
    node_identifier    TEXT NOT NULL,
    context_identifier TEXT NOT NULL,
    confidence         DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (evidence_id, context_id, node_identifier, context_identifier)
);

CREATE INDEX IF NOT EXISTS idx_correlation_evidence_context_context
    ON correlation_evidence_context (context_id);
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
DROP TABLE IF EXISTS correlation_evidence_context;
DROP TYPE IF EXISTS correlation_context_source;
"#,
            )
            .await
            .map(|_| ())
    }
}
