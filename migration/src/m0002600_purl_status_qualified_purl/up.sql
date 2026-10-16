-- Preserve the original advisory identifier; qualifier interpretation belongs to correlation.
ALTER TABLE purl_status ADD COLUMN qualified_purl_id uuid
    REFERENCES qualified_purl(id);
CREATE INDEX purl_status_qualified_purl_idx ON purl_status(qualified_purl_id);

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

-- Evidence retains each matched advisory PURL instead of merging different source identifiers.
ALTER TABLE correlation_evidence DROP CONSTRAINT correlation_evidence_key;
CREATE UNIQUE INDEX correlation_evidence_key ON correlation_evidence (
    sbom_id, node_id, advisory_id, vulnerability_id, extractor, status,
    (md5(CASE WHEN extractor LIKE 'purl%' THEN coalesce(matched_value ->> 'identifier', '') ELSE '' END))
);
