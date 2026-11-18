-- Advisory context PURLs are stored as canonical strings; SBOM PURLs are JSONB.
-- Decode to bytes to compare without depending on a particular percent-encoding
-- spelling or converting a potentially malformed byte sequence to text.
CREATE OR REPLACE FUNCTION legacy_context_purl_bytes(value text) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT
AS $$
    SELECT CASE WHEN strpos(value, '%') = 0 THEN convert_to(value, 'UTF8')
    ELSE (
        SELECT decode(string_agg(
            COALESCE(parts[1], encode(convert_to(COALESCE(parts[2], '%'), 'UTF8'), 'hex')),
            '' ORDER BY ord
        ), 'hex')
        FROM regexp_matches(value, '%([0-9A-Fa-f]{2})|([^%]+)|%', 'g')
             WITH ORDINALITY AS chunks(parts, ord)
    ) END
$$;

-- Assert only the version and qualifiers the advisory actually states.
-- This runs only for PURLs of the matched component or a Describes target.
CREATE OR REPLACE FUNCTION legacy_context_purl_matches(stated text, package jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT
AS $$
    SELECT COALESCE(
        parts[1] = package->>'ty'
        AND legacy_context_purl_bytes(NULLIF(rtrim(parts[2], '/'), '')) IS NOT DISTINCT FROM
            convert_to(package->>'namespace', 'UTF8')
        AND legacy_context_purl_bytes(parts[3]) = convert_to(package->>'name', 'UTF8')
        AND (parts[4] IS NULL OR
             legacy_context_purl_bytes(parts[4]) = convert_to(package->>'version', 'UTF8'))
        AND NOT EXISTS (
            SELECT 1 FROM unnest(string_to_array(parts[5], '&')) AS qualifiers(q)
            WHERE legacy_context_purl_bytes(substring(q FROM strpos(q, '=') + 1))
                  IS DISTINCT FROM
                  convert_to(package #>> ARRAY['qualifiers', split_part(q, '=', 1)], 'UTF8')
        ),
        false
    )
    FROM regexp_match(stated, '^pkg:([^/]+)/((?:@?[^/@?#]+/)*)([^/@?#]+)(?:@([^?#]+))?(?:[?]([^#]+))?$') AS matched(parts)
$$;
