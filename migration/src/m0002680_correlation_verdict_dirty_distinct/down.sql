CREATE OR REPLACE FUNCTION correlation_verdict_rows_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM correlation_verdict_dirty(ARRAY(SELECT sbom_id FROM new_rows));
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM correlation_verdict_dirty(ARRAY(SELECT sbom_id FROM old_rows));
    ELSE
        PERFORM correlation_verdict_dirty(ARRAY(
            SELECT sbom_id FROM old_rows UNION SELECT sbom_id FROM new_rows));
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION correlation_verdict_context_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM correlation_verdict_dirty(ARRAY(SELECT e.sbom_id FROM new_rows n
            JOIN correlation_evidence e ON e.id = n.evidence_id));
    ELSIF TG_OP = 'DELETE' THEN
        PERFORM correlation_verdict_dirty(ARRAY(SELECT e.sbom_id FROM old_rows o
            JOIN correlation_evidence e ON e.id = o.evidence_id));
    ELSE
        PERFORM correlation_verdict_dirty(ARRAY(SELECT e.sbom_id FROM correlation_evidence e
            WHERE e.id IN (SELECT evidence_id FROM old_rows UNION SELECT evidence_id FROM new_rows)));
    END IF;
    RETURN NULL;
END $$;
