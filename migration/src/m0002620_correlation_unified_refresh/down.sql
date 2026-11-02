LOCK TABLE change_log IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE VIEW correlation_verdict_freshness AS
SELECT s.sbom_id, s.generation, s.completed_at, r.revision required_revision,
    NULLIF(s.completed_revision, 0) completed_revision,
    CASE WHEN s.generation IS NULL THEN 'unknown'
         WHEN s.input_revision <> s.completed_input_revision OR s.completed_revision <> r.revision
           OR e.completed_revision IS DISTINCT FROM x.revision
           OR EXISTS (SELECT 1 FROM correlation_extraction_queue q
               WHERE q.entity_type = 'advisory' OR q.entity_id = s.sbom_id)
         THEN 'stale' ELSE 'current' END status
FROM correlation_verdict_state s CROSS JOIN correlation_verdict_revision r
CROSS JOIN correlation_extraction_revision x
LEFT JOIN correlation_extraction_state e USING(sbom_id);

ALTER TABLE correlation_refresh_job ADD COLUMN IF NOT EXISTS cursor uuid,
    ADD COLUMN IF NOT EXISTS cursor_revision bigint;

-- The previous schema extracts never-extracted SBOMs from the ingestion queue only.
INSERT INTO correlation_extraction_queue(id, entity_type, entity_id)
    SELECT gen_random_uuid(), 'sbom', sbom_id FROM correlation_extraction_state
    WHERE completed_revision = 0;

CREATE OR REPLACE FUNCTION correlation_extraction_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.operation = 'added' AND NEW.entity_type IN ('sbom', 'advisory') AND NEW.entity_id IS NOT NULL THEN
        INSERT INTO correlation_extraction_queue(id, entity_type, entity_id)
            VALUES (NEW.id, NEW.entity_type, NEW.entity_id);
    END IF;
    RETURN NEW;
END $$;
