use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Create denormalized label lookup tables that mirror the
        // key/value pairs stored in the JSONB `labels` column of
        // `advisory` and `sbom`. Each row holds one key/value pair
        // plus a pre-computed `key_value` text column used for
        // trigram searches.
        //
        // Triggers on the source tables keep these in sync on every
        // INSERT, UPDATE, and DELETE.
        db.execute_unprepared(
            r#"
-- advisory labels
CREATE TABLE advisory_label (
    advisory_id UUID NOT NULL
        REFERENCES advisory (id) ON DELETE CASCADE,
    key   TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    key_value TEXT NOT NULL,
    PRIMARY KEY (advisory_id, key)
);

CREATE INDEX advisory_label_kv_trgm_idx
    ON advisory_label USING GIN (key_value gin_trgm_ops);

-- sbom labels
CREATE TABLE sbom_label (
    sbom_id UUID NOT NULL
        REFERENCES sbom (sbom_id) ON DELETE CASCADE,
    key   TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    key_value TEXT NOT NULL,
    PRIMARY KEY (sbom_id, key)
);

CREATE INDEX sbom_label_kv_trgm_idx
    ON sbom_label USING GIN (key_value gin_trgm_ops);

-- Shared helper: build the key_value search text from a key and value.
CREATE OR REPLACE FUNCTION label_key_value(k TEXT, v TEXT)
RETURNS TEXT LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN v IS NULL OR v = '' THEN k
        ELSE k || '=' || v
    END;
$$;

-- Trigger function for advisory labels
CREATE OR REPLACE FUNCTION advisory_label_sync() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
        DELETE FROM advisory_label
        WHERE advisory_id = OLD.id;
    END IF;
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        INSERT INTO advisory_label (advisory_id, key, value, key_value)
        SELECT
            NEW.id,
            kv.key,
            COALESCE(kv.value, ''),
            label_key_value(kv.key, kv.value)
        FROM jsonb_each_text(NEW.labels) AS kv;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER advisory_label_sync_trg
    AFTER INSERT OR UPDATE OF labels OR DELETE ON advisory
    FOR EACH ROW EXECUTE FUNCTION advisory_label_sync();

-- Trigger function for sbom labels
CREATE OR REPLACE FUNCTION sbom_label_sync() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
        DELETE FROM sbom_label
        WHERE sbom_id = OLD.sbom_id;
    END IF;
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        INSERT INTO sbom_label (sbom_id, key, value, key_value)
        SELECT
            NEW.sbom_id,
            kv.key,
            COALESCE(kv.value, ''),
            label_key_value(kv.key, kv.value)
        FROM jsonb_each_text(NEW.labels) AS kv;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER sbom_label_sync_trg
    AFTER INSERT OR UPDATE OF labels OR DELETE ON sbom
    FOR EACH ROW EXECUTE FUNCTION sbom_label_sync();

-- Backfill from existing data
INSERT INTO advisory_label (advisory_id, key, value, key_value)
SELECT
    a.id,
    kv.key,
    COALESCE(kv.value, ''),
    label_key_value(kv.key, kv.value)
FROM advisory a, jsonb_each_text(a.labels) AS kv;

INSERT INTO sbom_label (sbom_id, key, value, key_value)
SELECT
    s.sbom_id,
    kv.key,
    COALESCE(kv.value, ''),
    label_key_value(kv.key, kv.value)
FROM sbom s, jsonb_each_text(s.labels) AS kv;
"#,
        )
        .await
        .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
DROP TRIGGER IF EXISTS sbom_label_sync_trg ON sbom;
DROP FUNCTION IF EXISTS sbom_label_sync;
DROP TABLE IF EXISTS sbom_label;

DROP TRIGGER IF EXISTS advisory_label_sync_trg ON advisory;
DROP FUNCTION IF EXISTS advisory_label_sync;
DROP TABLE IF EXISTS advisory_label;

DROP FUNCTION IF EXISTS label_key_value;
"#,
        )
        .await
        .map(|_| ())?;

        Ok(())
    }
}
