-- Store the matched value and the confidence factors with each evidence row again.

DROP VIEW IF EXISTS correlation_evidence_detail;

CREATE TABLE correlation_evidence_old (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    sbom_id uuid NOT NULL,
    node_id text NOT NULL,
    advisory_id uuid NOT NULL,
    vulnerability_id text NOT NULL,
    status assertion_status NOT NULL,
    confidence double precision NOT NULL,
    extractor text NOT NULL,
    matched_value jsonb,
    confidence_factors jsonb NOT NULL DEFAULT '[]'::jsonb,
    source_assertions jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

INSERT INTO correlation_evidence_old (id, sbom_id, node_id, advisory_id, vulnerability_id, status, confidence, extractor, matched_value, confidence_factors, source_assertions, created_at)
SELECT e.id, e.sbom_id, e.node_id, e.advisory_id, e.vulnerability_id, e.status, e.confidence, e.extractor, m.value, coalesce(f.value, '[]'::jsonb), e.source_assertions, e.created_at
FROM correlation_evidence e
LEFT JOIN correlation_matched_value m ON m.id = e.matched_value_id
LEFT JOIN correlation_confidence_factors f ON f.id = e.confidence_factors_id;

ALTER TABLE correlation_evidence_context DROP CONSTRAINT IF EXISTS correlation_evidence_context_evidence_id_fkey;
DROP TABLE correlation_evidence;
ALTER TABLE correlation_evidence_old RENAME TO correlation_evidence;

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

DROP TABLE IF EXISTS correlation_confidence_factors;
DROP TABLE IF EXISTS correlation_matched_value;
DROP FUNCTION IF EXISTS correlation_detail_id(jsonb);
