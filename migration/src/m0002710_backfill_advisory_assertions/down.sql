CREATE OR REPLACE FUNCTION correlation_verdict_global_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE correlation_verdict_revision SET revision = revision + 1, changed_at = clock_timestamp();
    RETURN NULL;
END $$;
