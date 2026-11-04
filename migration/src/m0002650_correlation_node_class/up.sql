-- Nodes of an SBOM with the same evidence inputs form a class. Its evidence and verdicts are
-- stored once, for the representative node. An SBOM without rows here (not extracted since) has
-- its evidence and verdicts stored per node.
CREATE TABLE IF NOT EXISTS correlation_node_class (
    sbom_id UUID NOT NULL REFERENCES sbom (sbom_id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    representative_node_id TEXT NOT NULL,
    PRIMARY KEY (sbom_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_correlation_node_class_representative
    ON correlation_node_class (sbom_id, representative_node_id);

-- extract all SBOMs again, storing their evidence per class
UPDATE correlation_extraction_revision SET revision = revision + 1;
