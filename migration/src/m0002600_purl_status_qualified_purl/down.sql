DROP VIEW purl_status_effective;
DROP INDEX purl_status_qualified_purl_idx;
ALTER TABLE purl_status DROP COLUMN qualified_purl_id;

DROP INDEX correlation_evidence_key;
-- These are derived records: retain one per legacy key on rollback; re-extraction rebuilds them.
DELETE FROM correlation_evidence a USING correlation_evidence b
    WHERE a.sbom_id = b.sbom_id AND a.node_id = b.node_id
      AND a.advisory_id = b.advisory_id AND a.vulnerability_id = b.vulnerability_id
      AND a.extractor = b.extractor AND a.status = b.status AND a.id > b.id;
ALTER TABLE correlation_evidence ADD CONSTRAINT correlation_evidence_key
    UNIQUE (sbom_id, node_id, advisory_id, vulnerability_id, extractor, status);
