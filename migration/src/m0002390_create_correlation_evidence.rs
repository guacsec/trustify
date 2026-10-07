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
CREATE TYPE assertion_status AS ENUM (
    'affected', 'fixed', 'not_affected',
    'under_investigation', 'recommended'
);

CREATE TYPE match_dimension AS ENUM ('digest', 'purl', 'cpe');

CREATE TABLE correlation_evidence (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id           UUID NOT NULL REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    node_id           TEXT NOT NULL,
    advisory_id       UUID NOT NULL REFERENCES advisory(id) ON DELETE CASCADE,
    vulnerability_id  TEXT NOT NULL,
    status            assertion_status NOT NULL,
    match_dimension   match_dimension NOT NULL,
    confidence        DOUBLE PRECISION NOT NULL,
    extractor         TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (sbom_id, node_id, advisory_id, vulnerability_id, extractor)
);

CREATE INDEX idx_correlation_evidence_sbom
    ON correlation_evidence (sbom_id);

CREATE INDEX idx_correlation_evidence_advisory
    ON correlation_evidence (advisory_id);
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
DROP TABLE IF EXISTS correlation_evidence;
DROP TYPE IF EXISTS match_dimension;
DROP TYPE IF EXISTS assertion_status;
"#,
            )
            .await
            .map(|_| ())
    }
}
