-- Preserve source identity and distinguish default statuses on existing data.
ALTER TABLE purl_status ADD COLUMN is_default boolean NOT NULL DEFAULT false;
ALTER TABLE purl_status ADD COLUMN qualified_purl_id uuid REFERENCES qualified_purl(id);
CREATE INDEX purl_status_qualified_purl_idx ON purl_status(qualified_purl_id);
ALTER TABLE purl_status ADD COLUMN source_provider jsonb;
ALTER TABLE sbom_package ADD COLUMN supplier jsonb;

CREATE TABLE correlation_provider_alias (
    id uuid PRIMARY KEY, revision uuid NOT NULL,
    provider text NOT NULL UNIQUE, aliases jsonb NOT NULL
);
INSERT INTO correlation_provider_alias VALUES
    ('019dc7a4-6a00-7000-8000-000000000010', '019dc7a4-6a00-7000-8000-000000000010',
     'https://www.redhat.com', '["namespace:https://www.redhat.com","name:Red Hat","name:Red Hat, Inc.","name:Red Hat Product Security","purl:rpm/redhat","distro:rhel","cpe-vendor:redhat"]'),
    ('019dc7a4-6a00-7000-8000-000000000011', '019dc7a4-6a00-7000-8000-000000000011',
     'https://www.suse.com', '["namespace:https://www.suse.com","name:SUSE","name:SUSE Linux Products GmbH","purl:rpm/suse","distro:sles","distro:sle","cpe-vendor:suse"]');

-- A bridge for the fundamental APIs, until they use the verdicts of the correlation engine.
--
-- Ingestion only stores what advisories state. For a publisher enabling the correlation option
-- `fixed_is_first_fixed` (Red Hat by default), a `fixed` version also means that earlier
-- versions are affected. These views add such `affected` rows at query time, nothing is stored.
--
-- A derived row keeps the `version_range_id` of the stated `fixed` row, and its range is the
-- derived row of `version_range_effective` with the same ID. Join both views on the ID and on
-- `derived`. `stated_id` is the ID of the stated row (e.g. for its remediations).

-- Each view is a single query over its table, crossed with the two values of `derived` (no
-- `UNION ALL`), so that the planner inlines it, and joins on it can use the table's indexes.

-- The stated ranges, plus "below" each exact version.
CREATE OR REPLACE VIEW version_range_effective AS
    SELECT
        vr.id,
        vr.version_scheme_id,
        CASE WHEN d.derived THEN NULL ELSE vr.low_version END AS low_version,
        CASE WHEN d.derived THEN NULL ELSE vr.low_inclusive END AS low_inclusive,
        vr.high_version,
        CASE WHEN d.derived THEN false ELSE vr.high_inclusive END AS high_inclusive,
        d.derived
    FROM version_range vr
    CROSS JOIN (VALUES (false), (true)) AS d (derived)
    WHERE NOT d.derived
        OR (vr.low_version IS NOT NULL AND vr.low_version = vr.high_version);

-- The stated statuses, plus "affected" for each `fixed` of a publisher enabling
-- `fixed_is_first_fixed`.
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

-- Match a version against a range of `version_range_effective`, as `version_matches` does for
-- `version_range`.
CREATE OR REPLACE FUNCTION version_matches(version_p text, range_p version_range_effective)
    RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT version_matches(
        version_p,
        ROW(
            range_p.id, range_p.version_scheme_id, range_p.low_version, range_p.low_inclusive,
            range_p.high_version, range_p.high_inclusive
        )::version_range
    )
$$;
