CREATE TABLE remediation_cpe_assertion (
    remediation_id uuid NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    assertion_id uuid NOT NULL REFERENCES advisory_vulnerability_cpe(id) ON DELETE CASCADE,
    PRIMARY KEY (remediation_id, assertion_id)
);
CREATE INDEX idx_remediation_cpe_assertion_source ON remediation_cpe_assertion (assertion_id);

CREATE TABLE remediation_hash_assertion (
    remediation_id uuid NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    assertion_id uuid NOT NULL REFERENCES advisory_vulnerability_hash(id) ON DELETE CASCADE,
    PRIMARY KEY (remediation_id, assertion_id)
);
CREATE INDEX idx_remediation_hash_assertion_source ON remediation_hash_assertion (assertion_id);

CREATE TABLE remediation_product_identifier_assertion (
    remediation_id uuid NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    assertion_id uuid NOT NULL REFERENCES advisory_vulnerability_product_identifier(id) ON DELETE CASCADE,
    PRIMARY KEY (remediation_id, assertion_id)
);
CREATE INDEX idx_remediation_product_identifier_assertion_source ON remediation_product_identifier_assertion (assertion_id);
