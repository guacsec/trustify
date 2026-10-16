DROP VIEW purl_status_effective;
CREATE OR REPLACE VIEW purl_status_effective AS
    SELECT
        CASE WHEN d.derived
            THEN md5(ps.id::text || ':fixed_is_first_fixed')::uuid
            ELSE ps.id
        END AS id,
        ps.advisory_id,
        ps.vulnerability_id,
        CASE WHEN d.derived
            -- `slug` isn't unique: any of them
            THEN (SELECT id FROM status WHERE slug = 'affected' ORDER BY id LIMIT 1)
            ELSE ps.status_id
        END AS status_id,
        ps.base_purl_id,
        ps.version_range_id,
        ps.context_cpe_id,
        ps.assertion_context_id,
        d.derived,
        ps.id AS stated_id,
        ps.is_default,
        ps.qualified_purl_id
    FROM purl_status ps
    CROSS JOIN (VALUES (false), (true)) AS d (derived)
    WHERE NOT ps.is_default AND (NOT d.derived
        OR (
            -- `slug` isn't unique: the initial data has two `fixed`
            ps.status_id IN (SELECT id FROM status WHERE slug = 'fixed')
            AND EXISTS (
                SELECT 1
                FROM advisory a
                JOIN correlation_option o
                    ON o.key = 'fixed_is_first_fixed'
                    AND o.value = 'true'::jsonb
                    AND o.publisher_namespace = rtrim(a.publisher_namespace, '/')
                WHERE a.id = ps.advisory_id
            )
        ));
-- Revert source splitting before restoring the old unique evidence key.
DELETE FROM correlation_evidence a USING correlation_evidence b
WHERE a.sbom_id=b.sbom_id AND a.node_id=b.node_id AND a.advisory_id=b.advisory_id
 AND a.vulnerability_id=b.vulnerability_id AND a.extractor=b.extractor AND a.status=b.status
 AND (CASE WHEN a.extractor LIKE 'purl%' THEN coalesce(a.matched_value->>'identifier','') ELSE '' END)
   = (CASE WHEN b.extractor LIKE 'purl%' THEN coalesce(b.matched_value->>'identifier','') ELSE '' END)
 AND a.id>b.id;
DROP INDEX correlation_evidence_key;
CREATE UNIQUE INDEX correlation_evidence_key ON correlation_evidence (
 sbom_id,node_id,advisory_id,vulnerability_id,extractor,status,
 (md5(CASE WHEN extractor LIKE 'purl%' THEN coalesce(matched_value->>'identifier','') ELSE '' END))
);
UPDATE correlation_evidence SET matched_value=matched_value-'source_provider' WHERE jsonb_typeof(matched_value)='object';
ALTER TABLE sbom_package DROP COLUMN supplier;
ALTER TABLE purl_status DROP COLUMN source_provider;
ALTER TABLE advisory_vulnerability_cpe DROP COLUMN source_provider;
DROP TABLE correlation_weight_policy;
DROP TABLE correlation_provider_alias;
