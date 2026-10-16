ALTER TABLE sbom_package ADD COLUMN supplier jsonb;
ALTER TABLE purl_status ADD COLUMN source_provider jsonb;
ALTER TABLE advisory_vulnerability_cpe ADD COLUMN source_provider jsonb;
CREATE TABLE correlation_weight_policy (
    id uuid PRIMARY KEY, revision uuid NOT NULL,
    scope jsonb NOT NULL UNIQUE, priority integer NOT NULL DEFAULT 0,
    weights jsonb NOT NULL
);
CREATE TABLE correlation_provider_alias (
    id uuid PRIMARY KEY, revision uuid NOT NULL,
    provider text NOT NULL UNIQUE, aliases jsonb NOT NULL
);
INSERT INTO correlation_provider_alias VALUES
    ('019dc7a4-6a00-7000-8000-000000000010', '019dc7a4-6a00-7000-8000-000000000010',
     'https://www.redhat.com', '["namespace:https://www.redhat.com","name:Red Hat","name:Red Hat, Inc.","name:Red Hat Product Security","purl:rpm/redhat","distro:rhel","cpe-vendor:redhat"]'),
    ('019dc7a4-6a00-7000-8000-000000000011', '019dc7a4-6a00-7000-8000-000000000011',
     'https://www.suse.com', '["namespace:https://www.suse.com","name:SUSE","name:SUSE Linux Products GmbH","purl:rpm/suse","distro:sles","distro:sle","cpe-vendor:suse"]');
-- Existing CVE statements merged CNA and ADP sources. Do not attribute them all to the CNA.
UPDATE correlation_evidence e
SET matched_value = coalesce(e.matched_value, '{"identifier":""}'::jsonb)
    || '{"source_provider":{"identifiers":[],"unavailable":true}}'::jsonb
FROM advisory a
WHERE e.advisory_id = a.id AND a.labels->>'type' = 'cve'
    AND (e.matched_value IS NULL OR jsonb_typeof(e.matched_value) = 'object')
    AND NOT coalesce(e.matched_value ? 'source_provider', false);
-- Preserve distinct assertion providers even when their identifiers and statuses agree.
DROP INDEX correlation_evidence_key;
CREATE UNIQUE INDEX correlation_evidence_key ON correlation_evidence (
    sbom_id, node_id, advisory_id, vulnerability_id, extractor, status,
    (md5(CASE WHEN extractor LIKE 'purl%' THEN coalesce(matched_value->>'identifier','') ELSE '' END)),
    (md5(coalesce((matched_value->'source_provider')::text, '')))
);
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
        ps.qualified_purl_id,
        ps.source_provider
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
