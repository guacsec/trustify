DROP TABLE remediation_product_identifier_assertion;
DROP TABLE remediation_hash_assertion;
DROP TABLE remediation_cpe_assertion;
ALTER TABLE correlation_evidence DROP COLUMN source_assertions;

-- The previous index cannot represent several ranges of the same identifier/context.
-- Keep one deterministic representative on downgrade; reimport restores the full scopes.
DROP INDEX idx_advisory_vuln_product_id_key;
DELETE FROM advisory_vulnerability_product_identifier a
USING advisory_vulnerability_product_identifier b
WHERE (a.advisory_id, a.vulnerability_id, a.identifier_type, a.value, a.status, a.assertion_context_id)
    IS NOT DISTINCT FROM
      (b.advisory_id, b.vulnerability_id, b.identifier_type, b.value, b.status, b.assertion_context_id)
  AND a.id > b.id;
CREATE UNIQUE INDEX idx_advisory_vuln_product_id_key
    ON advisory_vulnerability_product_identifier
       (advisory_id, vulnerability_id, identifier_type, value, status, assertion_context_id)
    NULLS NOT DISTINCT;
