-- SBOMs are refreshed through the same automatically scheduled job, whether never
-- extracted (revision 0) or outdated by a settings change. Only advisories, whose
-- extraction is incremental per change, remain on the ingestion queue.
LOCK TABLE change_log IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION correlation_extraction_enqueue() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.operation = 'added' AND NEW.entity_type = 'advisory' AND NEW.entity_id IS NOT NULL THEN
        INSERT INTO correlation_extraction_queue(id, entity_type, entity_id)
            VALUES (NEW.id, NEW.entity_type, NEW.entity_id);
    END IF;
    RETURN NEW;
END $$;

-- Their extraction state is already behind the current revision, so the job covers them.
DELETE FROM correlation_extraction_queue WHERE entity_type = 'sbom';

-- Jobs select the next pending document not yet attempted, so they need no cursor.
ALTER TABLE correlation_refresh_job DROP COLUMN IF EXISTS cursor, DROP COLUMN IF EXISTS cursor_revision;

CREATE OR REPLACE VIEW correlation_verdict_freshness AS
SELECT s.sbom_id, s.generation, s.completed_at, r.revision required_revision,
    NULLIF(s.completed_revision, 0) completed_revision,
    CASE WHEN s.generation IS NULL THEN 'unknown'
         WHEN s.input_revision <> s.completed_input_revision OR s.completed_revision <> r.revision
           OR e.completed_revision IS DISTINCT FROM x.revision
           OR EXISTS (SELECT 1 FROM correlation_extraction_queue q WHERE q.entity_type = 'advisory')
         THEN 'stale' ELSE 'current' END status
FROM correlation_verdict_state s CROSS JOIN correlation_verdict_revision r
CROSS JOIN correlation_extraction_revision x
LEFT JOIN correlation_extraction_state e USING(sbom_id);
