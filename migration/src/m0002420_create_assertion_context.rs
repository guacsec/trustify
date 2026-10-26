use sea_orm_migration::prelude::*;

/// The shared product context of advisory assertions, distilled to identifiers, e.g.
/// "golang as a default component of Red Hat Storage 3 (`cpe:/a:redhat:storage:3`)".
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
    CREATE TYPE assertion_context_category AS ENUM (
        'default_component_of', 'external_component_of', 'installed_on', 'installed_with',
        'optional_component_of'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE context_identifier_kind AS ENUM (
        'cpe', 'purl', 'model_number', 'serial_number', 'sku', 'digest'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS assertion_context (
    id       UUID PRIMARY KEY,
    category assertion_context_category,
    name     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assertion_context_identifier (
    context_id UUID NOT NULL REFERENCES assertion_context(id) ON DELETE CASCADE,
    kind       context_identifier_kind NOT NULL,
    value      TEXT NOT NULL,
    -- set for kind = cpe, for CPE matching
    cpe_id     UUID REFERENCES cpe(id),
    PRIMARY KEY (context_id, kind, value)
);

CREATE INDEX IF NOT EXISTS idx_assertion_context_identifier_cpe
    ON assertion_context_identifier (cpe_id);

ALTER TABLE purl_status
    ADD COLUMN IF NOT EXISTS assertion_context_id UUID REFERENCES assertion_context(id);
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
-- Contextual rows cannot be represented by the previous schema.
DELETE FROM remediation_purl_status WHERE purl_status_id IN (
    SELECT id FROM purl_status WHERE assertion_context_id IS NOT NULL
);
DELETE FROM purl_status WHERE assertion_context_id IS NOT NULL;
ALTER TABLE purl_status DROP COLUMN IF EXISTS assertion_context_id;

DROP TABLE IF EXISTS assertion_context_identifier;
DROP TABLE IF EXISTS assertion_context;
DROP TYPE IF EXISTS context_identifier_kind;
DROP TYPE IF EXISTS assertion_context_category;
"#,
            )
            .await
            .map(|_| ())
    }
}
