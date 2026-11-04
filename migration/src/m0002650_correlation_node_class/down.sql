DROP TABLE IF EXISTS correlation_node_class;

-- evidence was only stored for the representatives, extract all SBOMs again
UPDATE correlation_extraction_revision SET revision = revision + 1;
