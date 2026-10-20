-- Keep ingestion/deletion from slipping between the backfill and trigger installation.
LOCK TABLE sbom IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE correlation_extraction_revision (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0)
);
INSERT INTO correlation_extraction_revision DEFAULT VALUES;

-- Revision zero is reserved for documents with no completed full extraction.
CREATE TABLE correlation_extraction_count (
    revision bigint NOT NULL,
    -- Use random UUID suffix bits: UUIDv7's leading bytes are shared by new documents.
    shard smallint NOT NULL CHECK (shard >= 0 AND shard < 64),
    documents bigint NOT NULL CHECK (documents >= 0),
    PRIMARY KEY (revision, shard)
);
CREATE TABLE correlation_extraction_state (
    sbom_id uuid PRIMARY KEY REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    completed_revision bigint NOT NULL DEFAULT 0,
    completed_at timestamptz
);
CREATE INDEX correlation_extraction_state_revision ON correlation_extraction_state(completed_revision, sbom_id);

INSERT INTO correlation_extraction_state(sbom_id) SELECT sbom_id FROM sbom;
INSERT INTO correlation_extraction_count
    SELECT 0, get_byte(uuid_send(sbom_id),15) % 64, count(*) FROM sbom GROUP BY 2;

CREATE FUNCTION correlation_extraction_count_update() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bucket smallint;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.completed_revision = NEW.completed_revision THEN RETURN NEW; END IF;
    IF TG_OP = 'DELETE' THEN bucket := get_byte(uuid_send(OLD.sbom_id),15) % 64;
    ELSE bucket := get_byte(uuid_send(NEW.sbom_id),15) % 64; END IF;
    IF TG_OP <> 'INSERT' THEN
        UPDATE correlation_extraction_count SET documents = documents - 1
            WHERE revision = OLD.completed_revision AND shard = bucket;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        INSERT INTO correlation_extraction_count(revision, shard, documents) VALUES (NEW.completed_revision, bucket, 1)
        ON CONFLICT (revision, shard) DO UPDATE SET documents = correlation_extraction_count.documents + 1;
        RETURN NEW;
    END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER correlation_extraction_count_update AFTER INSERT OR UPDATE OR DELETE ON correlation_extraction_state
    FOR EACH ROW EXECUTE FUNCTION correlation_extraction_count_update();

CREATE FUNCTION correlation_extraction_state_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO correlation_extraction_state(sbom_id) VALUES (NEW.sbom_id);
    RETURN NEW;
END $$;
CREATE TRIGGER correlation_extraction_state_insert AFTER INSERT ON sbom
    FOR EACH ROW EXECUTE FUNCTION correlation_extraction_state_insert();

-- Database-side invalidation also covers direct SQL changes. Readers take a shared
-- lock on this singleton before matching, so settings cannot change mid-extraction.
CREATE FUNCTION correlation_extraction_invalidate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.key, OLD.publisher_namespace, OLD.value)
        IS NOT DISTINCT FROM (NEW.key, NEW.publisher_namespace, NEW.value) THEN RETURN NEW; END IF;
    UPDATE correlation_extraction_revision SET revision = revision + 1;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER correlation_extraction_invalidate BEFORE INSERT OR UPDATE OR DELETE ON correlation_option
    FOR EACH ROW EXECUTE FUNCTION correlation_extraction_invalidate();

CREATE TABLE correlation_refresh_job (
    id uuid PRIMARY KEY,
    revision bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'superseded')),
    cursor uuid,
    cursor_revision bigint,
    processed bigint NOT NULL DEFAULT 0,
    failed bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE UNIQUE INDEX correlation_refresh_one_active ON correlation_refresh_job ((true)) WHERE status IN ('queued', 'running');
CREATE INDEX correlation_refresh_latest ON correlation_refresh_job(created_at DESC, id DESC);
CREATE TABLE correlation_refresh_outcome (
    job_id uuid NOT NULL REFERENCES correlation_refresh_job(id) ON DELETE CASCADE,
    sbom_id uuid NOT NULL,
    error text,
    PRIMARY KEY (job_id, sbom_id)
);
CREATE INDEX correlation_refresh_failures ON correlation_refresh_outcome(job_id, sbom_id) WHERE error IS NOT NULL;
