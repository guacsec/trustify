-- Keep ingestion from slipping between backfill and trigger installation.
LOCK TABLE change_log IN SHARE ROW EXCLUSIVE MODE;

-- Independent of change_log retention: pending work must survive log cleanup.
-- Successful work is removed atomically with its evidence writes. Thus this table
-- contains only the backlog, including failures awaiting automatic retry.
CREATE TABLE correlation_extraction_queue (
    id uuid PRIMARY KEY,
    entity_type text NOT NULL CHECK (entity_type IN ('sbom', 'advisory')),
    entity_id uuid NOT NULL,
    queued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts bigint NOT NULL DEFAULT 0,
    retry_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX correlation_extraction_queue_ready ON correlation_extraction_queue(retry_at, queued_at, id);

CREATE FUNCTION correlation_extraction_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.operation = 'added' AND NEW.entity_type IN ('sbom', 'advisory') AND NEW.entity_id IS NOT NULL THEN
        INSERT INTO correlation_extraction_queue(id, entity_type, entity_id)
            VALUES (NEW.id, NEW.entity_type, NEW.entity_id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER correlation_extraction_enqueue AFTER INSERT ON change_log
    FOR EACH ROW EXECUTE FUNCTION correlation_extraction_enqueue();

-- Earlier event delivery had no durable acknowledgement. Recheck existing
-- documents rather than claiming that their extraction already completed.
INSERT INTO correlation_extraction_queue(id, entity_type, entity_id)
    SELECT gen_random_uuid(), 'sbom', sbom_id FROM sbom;
INSERT INTO correlation_extraction_queue(id, entity_type, entity_id)
    SELECT gen_random_uuid(), 'advisory', id FROM advisory;
