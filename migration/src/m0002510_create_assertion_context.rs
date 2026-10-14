use sea_orm_migration::prelude::*;

/// The product context of advisory assertions: the product (platform) a statement is made in,
/// distilled to its identifiers, e.g. "golang as a default component of Red Hat Storage 3
/// (`cpe:/a:redhat:storage:3`)".
///
/// Contexts are shared across advisories. The assertion tables read by the correlation engine
/// reference the context of each statement, a statement in several products is one row each.
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

-- purl status and CPE assertions: the context is part of their deterministic ID

ALTER TABLE purl_status
    ADD COLUMN IF NOT EXISTS assertion_context_id UUID REFERENCES assertion_context(id);
ALTER TABLE advisory_vulnerability_cpe
    ADD COLUMN IF NOT EXISTS assertion_context_id UUID REFERENCES assertion_context(id);

-- hash and product identifier assertions: a deterministic ID replaces the natural key, which
-- now includes the status and the context

ALTER TABLE advisory_vulnerability_hash
    ADD COLUMN IF NOT EXISTS assertion_context_id UUID REFERENCES assertion_context(id),
    ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE advisory_vulnerability_hash
    DROP CONSTRAINT IF EXISTS advisory_vulnerability_hash_pkey,
    ADD PRIMARY KEY (id),
    ALTER COLUMN id DROP DEFAULT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_vuln_hash_key
    ON advisory_vulnerability_hash
       (advisory_id, vulnerability_id, algorithm, value, status, assertion_context_id)
    NULLS NOT DISTINCT;

ALTER TABLE advisory_vulnerability_product_identifier
    ADD COLUMN IF NOT EXISTS assertion_context_id UUID REFERENCES assertion_context(id),
    ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE advisory_vulnerability_product_identifier
    DROP CONSTRAINT IF EXISTS advisory_vulnerability_product_identifier_pkey,
    ADD PRIMARY KEY (id),
    ALTER COLUMN id DROP DEFAULT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_vuln_product_id_key
    ON advisory_vulnerability_product_identifier
       (advisory_id, vulnerability_id, identifier_type, value, status, assertion_context_id)
    NULLS NOT DISTINCT;
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
-- the natural keys don't include status and context: keep one row each

DELETE FROM advisory_vulnerability_hash a
    USING advisory_vulnerability_hash b
    WHERE a.advisory_id = b.advisory_id AND a.vulnerability_id = b.vulnerability_id
      AND a.algorithm = b.algorithm AND a.value = b.value AND a.id > b.id;
DROP INDEX IF EXISTS idx_advisory_vuln_hash_key;
ALTER TABLE advisory_vulnerability_hash
    DROP CONSTRAINT IF EXISTS advisory_vulnerability_hash_pkey,
    DROP COLUMN IF EXISTS id,
    DROP COLUMN IF EXISTS assertion_context_id,
    ADD PRIMARY KEY (advisory_id, vulnerability_id, algorithm, value);

DELETE FROM advisory_vulnerability_product_identifier a
    USING advisory_vulnerability_product_identifier b
    WHERE a.advisory_id = b.advisory_id AND a.vulnerability_id = b.vulnerability_id
      AND a.identifier_type = b.identifier_type AND a.value = b.value AND a.id > b.id;
DROP INDEX IF EXISTS idx_advisory_vuln_product_id_key;
ALTER TABLE advisory_vulnerability_product_identifier
    DROP CONSTRAINT IF EXISTS advisory_vulnerability_product_identifier_pkey,
    DROP COLUMN IF EXISTS id,
    DROP COLUMN IF EXISTS assertion_context_id,
    ADD PRIMARY KEY (advisory_id, vulnerability_id, identifier_type, value);

-- rows of a context can't be told apart without it, they are dropped (re-ingest to restore)
DELETE FROM remediation_purl_status WHERE purl_status_id IN (
    SELECT id FROM purl_status WHERE assertion_context_id IS NOT NULL
);
DELETE FROM purl_status WHERE assertion_context_id IS NOT NULL;
ALTER TABLE purl_status DROP COLUMN IF EXISTS assertion_context_id;
DELETE FROM advisory_vulnerability_cpe WHERE assertion_context_id IS NOT NULL;
ALTER TABLE advisory_vulnerability_cpe DROP COLUMN IF EXISTS assertion_context_id;

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
