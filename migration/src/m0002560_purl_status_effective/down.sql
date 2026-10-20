DROP FUNCTION IF EXISTS version_matches(text, version_range_effective);
DROP VIEW IF EXISTS purl_status_effective;
DROP VIEW IF EXISTS version_range_effective;

DELETE FROM remediation_purl_status WHERE purl_status_id IN (
    SELECT id FROM purl_status WHERE is_default
);
DELETE FROM purl_status WHERE is_default;
ALTER TABLE purl_status DROP COLUMN is_default;
ALTER TABLE purl_status DROP COLUMN qualified_purl_id;
ALTER TABLE purl_status DROP COLUMN source_provider;
ALTER TABLE sbom_package DROP COLUMN supplier;
DROP TABLE correlation_provider_alias;
