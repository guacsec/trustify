-- Store the matched value and the confidence factors of evidence once, instead of per row.
--
-- Both repeat across nodes: a statement matches many nodes with the same matched value, and
-- the confidence factors take few distinct values. The rows reference them by an ID derived from
-- the content (`correlation_detail_id`), computed by the database for both this migration and the
-- extraction, as `jsonb::text` is canonical.
--
-- There is no foreign key from the evidence to the values: removing unreferenced values (see
-- the correlation worker's cleanup) would scan the evidence once per removed value without an
-- index on the reference, which would cost about as much as the deduplication saves. Values are
-- written before the evidence referencing them, and only removed while no extraction runs.

CREATE OR REPLACE FUNCTION correlation_detail_id(value jsonb) RETURNS uuid
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $$ SELECT encode(substr(sha256(convert_to(value::text, 'UTF8')), 1, 16), 'hex')::uuid $$;

CREATE TABLE IF NOT EXISTS correlation_matched_value (
    id uuid PRIMARY KEY,
    value jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS correlation_confidence_factors (
    id uuid PRIMARY KEY,
    value jsonb NOT NULL
);

INSERT INTO correlation_matched_value (id, value)
SELECT correlation_detail_id(value), value
FROM (SELECT DISTINCT matched_value AS value FROM correlation_evidence WHERE matched_value IS NOT NULL) AS v
ON CONFLICT (id) DO NOTHING;

INSERT INTO correlation_confidence_factors (id, value)
SELECT correlation_detail_id(value), value
FROM (SELECT DISTINCT confidence_factors AS value FROM correlation_evidence) AS v
ON CONFLICT (id) DO NOTHING;

-- Rewrite the evidence into a new table, instead of updating it in place: an update would fire
-- the triggers marking the verdicts of every SBOM as changed, and leave the table at twice its
-- size until a full vacuum.
CREATE TABLE correlation_evidence_new (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    sbom_id uuid NOT NULL,
    node_id text NOT NULL,
    advisory_id uuid NOT NULL,
    vulnerability_id text NOT NULL,
    status assertion_status NOT NULL,
    confidence double precision NOT NULL,
    extractor text NOT NULL,
    matched_value_id uuid,
    confidence_factors_id uuid NOT NULL,
    source_assertions jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

INSERT INTO correlation_evidence_new (id, sbom_id, node_id, advisory_id, vulnerability_id, status, confidence, extractor, matched_value_id, confidence_factors_id, source_assertions, created_at)
SELECT id, sbom_id, node_id, advisory_id, vulnerability_id, status, confidence, extractor, correlation_detail_id(matched_value), correlation_detail_id(confidence_factors), source_assertions, created_at
FROM correlation_evidence;

ALTER TABLE correlation_evidence_context DROP CONSTRAINT IF EXISTS correlation_evidence_context_evidence_id_fkey;
DROP TABLE correlation_evidence;
ALTER TABLE correlation_evidence_new RENAME TO correlation_evidence;

ALTER TABLE correlation_evidence
    ADD CONSTRAINT correlation_evidence_pkey PRIMARY KEY (id),
    ADD CONSTRAINT correlation_evidence_sbom_id_fkey FOREIGN KEY (sbom_id) REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    ADD CONSTRAINT correlation_evidence_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES advisory(id) ON DELETE CASCADE,
    ADD CONSTRAINT correlation_evidence_source_assertions_check CHECK (jsonb_typeof(source_assertions) = 'array' AND jsonb_array_length(source_assertions) > 0);

CREATE INDEX IF NOT EXISTS idx_correlation_evidence_advisory ON correlation_evidence (advisory_id);
CREATE INDEX IF NOT EXISTS idx_correlation_evidence_group ON correlation_evidence (sbom_id, node_id, vulnerability_id);

ALTER TABLE correlation_evidence_context
    ADD CONSTRAINT correlation_evidence_context_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES correlation_evidence(id) ON DELETE CASCADE;

CREATE TRIGGER correlation_verdict_evidence_changed_ins AFTER INSERT ON correlation_evidence REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_rows_changed();
CREATE TRIGGER correlation_verdict_evidence_changed_upd AFTER UPDATE ON correlation_evidence REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_rows_changed();
CREATE TRIGGER correlation_verdict_evidence_changed_del AFTER DELETE ON correlation_evidence REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION correlation_verdict_rows_changed();

-- The evidence with its details, as it was stored before.
CREATE OR REPLACE VIEW correlation_evidence_detail AS
SELECT e.id, e.sbom_id, e.node_id, e.advisory_id, e.vulnerability_id, e.status, e.confidence, e.extractor, m.value AS matched_value, e.created_at, f.value AS confidence_factors, e.source_assertions
FROM correlation_evidence e
LEFT JOIN correlation_matched_value m ON m.id = e.matched_value_id
LEFT JOIN correlation_confidence_factors f ON f.id = e.confidence_factors_id;
