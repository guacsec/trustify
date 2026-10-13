-- The default status of a CVE record (`defaultStatus`): the status of all versions it doesn't list.
-- It is stored as an unbounded range, flagged as the default. It only applies to a version if no
-- listed statement of the same package does, which the correlation engine evaluates.

ALTER TABLE purl_status ADD COLUMN IF NOT EXISTS is_default boolean NOT NULL DEFAULT false;
ALTER TABLE advisory_vulnerability_cpe ADD COLUMN IF NOT EXISTS is_default boolean NOT NULL DEFAULT false;

-- The fundamental APIs don't evaluate defaults: their bridge view leaves them out.
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
        ps.is_default
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
