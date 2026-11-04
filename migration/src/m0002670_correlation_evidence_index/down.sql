CREATE INDEX IF NOT EXISTS idx_correlation_evidence_sbom
    ON correlation_evidence (sbom_id);

DROP INDEX IF EXISTS idx_correlation_evidence_group;

CREATE UNIQUE INDEX IF NOT EXISTS correlation_evidence_key ON correlation_evidence (
    sbom_id, node_id, advisory_id, vulnerability_id, extractor, status,
    (md5(CASE WHEN extractor LIKE 'purl%' THEN coalesce(matched_value->>'identifier','') ELSE '' END)),
    (md5(coalesce((matched_value->'source_provider')::text, '')))
);
