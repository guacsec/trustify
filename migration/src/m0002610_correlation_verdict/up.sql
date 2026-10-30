-- A revision change invalidates every snapshot without synchronously expanding a queue.
CREATE TABLE correlation_verdict_revision (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL DEFAULT 1,
    resolver_version integer NOT NULL DEFAULT 1,
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO correlation_verdict_revision DEFAULT VALUES;

CREATE TABLE correlation_verdict_publication (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    revision bigint NOT NULL DEFAULT 0
);
INSERT INTO correlation_verdict_publication DEFAULT VALUES;

CREATE TABLE correlation_verdict_state (
    sbom_id uuid PRIMARY KEY REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    input_revision bigint NOT NULL DEFAULT 1,
    completed_input_revision bigint NOT NULL DEFAULT 0,
    completed_revision bigint NOT NULL DEFAULT 0,
    generation uuid,
    completed_at timestamptz,
    queued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts bigint NOT NULL DEFAULT 0,
    retry_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX correlation_verdict_state_revision ON correlation_verdict_state(completed_revision, retry_at, sbom_id);
CREATE INDEX correlation_verdict_state_dirty ON correlation_verdict_state(retry_at, sbom_id)
    WHERE input_revision <> completed_input_revision;

CREATE TYPE verdict_status AS ENUM ('affected', 'fixed', 'not_affected', 'under_investigation', 'none');
CREATE TABLE correlation_verdict (
    sbom_id uuid NOT NULL REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    node_id text COLLATE "C" NOT NULL,
    vulnerability_id text COLLATE "C" NOT NULL,
    status verdict_status NOT NULL,
    snapshot jsonb NOT NULL,
    remediation_count bigint NOT NULL,
    PRIMARY KEY (sbom_id, node_id, vulnerability_id)
);
-- Search SBOMs by status, optionally constrained to a vulnerability, without reading payloads.
CREATE INDEX correlation_verdict_status ON correlation_verdict(status, sbom_id);
CREATE INDEX correlation_verdict_vulnerability ON correlation_verdict(vulnerability_id, status, sbom_id);

-- Marks each SBOM dirty once per call. Sorted ids keep the lock order stable across
-- concurrent writers.
CREATE FUNCTION correlation_verdict_dirty(ids uuid[]) RETURNS void LANGUAGE sql AS $$
    INSERT INTO correlation_verdict_state(sbom_id)
        SELECT sbom_id FROM sbom WHERE sbom_id = ANY(ids) ORDER BY sbom_id
    ON CONFLICT(sbom_id) DO UPDATE SET
        input_revision = correlation_verdict_state.input_revision + 1,
        queued_at = CASE WHEN correlation_verdict_state.input_revision = correlation_verdict_state.completed_input_revision
            THEN clock_timestamp() ELSE correlation_verdict_state.queued_at END,
        attempts = 0, retry_at = clock_timestamp();
$$;

-- Statement level: a per-row trigger would update the same state row once per inserted row,
-- which makes ingesting a large SBOM super-linear. PostgreSQL only allows transition tables
-- on single-event triggers, so each table gets one trigger per operation.
CREATE FUNCTION correlation_verdict_rows_changed() RETURNS trigger LANGUAGE plpgsql AS $$
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

-- Creates the insert, update and delete statement triggers `<name>_ins|_upd|_del` on a table.
CREATE FUNCTION correlation_verdict_create_triggers(tbl text, name text, func text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('CREATE TRIGGER %I AFTER INSERT ON %I REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION %I()', name || '_ins', tbl, func);
    EXECUTE format('CREATE TRIGGER %I AFTER UPDATE ON %I REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION %I()', name || '_upd', tbl, func);
    EXECUTE format('CREATE TRIGGER %I AFTER DELETE ON %I REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION %I()', name || '_del', tbl, func);
END $$;

SELECT correlation_verdict_create_triggers('correlation_evidence', 'correlation_verdict_evidence_changed', 'correlation_verdict_rows_changed');

CREATE FUNCTION correlation_verdict_global_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE correlation_verdict_revision SET revision = revision + 1, changed_at = clock_timestamp();
    RETURN NULL;
END $$;

-- These inputs can change a snapshot without writing an evidence row. Global invalidation
-- is conservative; it performs constant work on the write path and the worker sweeps lazily.
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['correlation_provider_alias', 'remediation', 'remediation_purl_status',
        'remediation_product_status', 'remediation_cpe_assertion', 'remediation_hash_assertion',
        'remediation_product_identifier_assertion', 'organization', 'assertion_context'] LOOP
        EXECUTE format('CREATE TRIGGER correlation_verdict_global_changed AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_global_changed()', t);
    END LOOP;
END $$;
CREATE TRIGGER correlation_verdict_global_changed AFTER UPDATE OR DELETE ON advisory
    FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_global_changed();
CREATE TRIGGER correlation_verdict_global_changed AFTER UPDATE ON vulnerability
    FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_global_changed();
CREATE TRIGGER correlation_verdict_global_changed AFTER UPDATE ON sbom
    FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_global_changed();
CREATE TRIGGER correlation_verdict_global_changed AFTER UPDATE ON sbom_package
    FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_global_changed();
CREATE TRIGGER correlation_verdict_global_changed AFTER UPDATE ON sbom_node
    FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_global_changed();
CREATE FUNCTION correlation_verdict_context_changed() RETURNS trigger LANGUAGE plpgsql AS $$
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
SELECT correlation_verdict_create_triggers('correlation_evidence_context', 'correlation_verdict_context_changed', 'correlation_verdict_context_changed');

-- Identifier and package graph changes also affect provider resolution and displayed details.
SELECT correlation_verdict_create_triggers(t, 'correlation_verdict_local_changed', 'correlation_verdict_rows_changed')
    FROM unnest(ARRAY['sbom_node_purl_ref', 'sbom_node_cpe_ref', 'sbom_node_product_identifier', 'package_relates_to_package']) t;
DROP FUNCTION correlation_verdict_create_triggers(text, text, text);

CREATE FUNCTION correlation_verdict_sbom_added() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM correlation_verdict_dirty(ARRAY[NEW.sbom_id]);
    RETURN NEW;
END $$;
CREATE TRIGGER correlation_verdict_sbom_added AFTER INSERT ON sbom
    FOR EACH ROW EXECUTE FUNCTION correlation_verdict_sbom_added();

-- Initial backfill is metadata only; the worker computes snapshots asynchronously.
INSERT INTO correlation_verdict_state(sbom_id) SELECT sbom_id FROM sbom;

-- Shared by verdict pages and SBOM search, so both report the same freshness semantics.
CREATE VIEW correlation_verdict_freshness AS
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
