-- Writing the statements of many documents would otherwise take a lock on the single row of
-- correlation_verdict_revision per document, until its commit, so documents would be processed one
-- at a time. A transaction opting out invalidates once, when it's done with all of them.
CREATE OR REPLACE FUNCTION correlation_verdict_global_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('trustify.correlation_defer_invalidation', true) = 'on' THEN
        RETURN NULL;
    END IF;
    UPDATE correlation_verdict_revision SET revision = revision + 1, changed_at = clock_timestamp();
    RETURN NULL;
END $$;
