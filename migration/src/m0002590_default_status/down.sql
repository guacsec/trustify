DROP VIEW IF EXISTS purl_status_effective;

DELETE FROM purl_status WHERE is_default;
DELETE FROM advisory_vulnerability_cpe WHERE is_default;

ALTER TABLE purl_status DROP COLUMN IF EXISTS is_default;
ALTER TABLE advisory_vulnerability_cpe DROP COLUMN IF EXISTS is_default;
