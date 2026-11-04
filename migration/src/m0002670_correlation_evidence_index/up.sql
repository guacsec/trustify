-- The unique key repeats what the deterministic evidence ID (the primary key) already makes
-- unique: it is derived from the same fields. Its size made every evidence insert expensive.
DROP INDEX IF EXISTS correlation_evidence_key;

-- The groups of verdicts, and node filters, within an SBOM. Also serves lookups by SBOM.
CREATE INDEX IF NOT EXISTS idx_correlation_evidence_group
    ON correlation_evidence (sbom_id, node_id, vulnerability_id);

DROP INDEX IF EXISTS idx_correlation_evidence_sbom;
