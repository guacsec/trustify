-- Create dictionary table for unique expanded license texts
CREATE TABLE IF NOT EXISTS expanded_license (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    expanded_text TEXT NOT NULL,
    text_hash TEXT GENERATED ALWAYS AS (md5(expanded_text)) STORED
);

-- Unique constraint on the generated hash column for deduplication
-- (handles long texts >2.7KB that exceed B-tree limits)
CREATE UNIQUE INDEX IF NOT EXISTS idx_expanded_license_text_hash
ON expanded_license (text_hash);

-- Create junction table mapping (sbom_id, license_id) → expanded_license_id
CREATE TABLE IF NOT EXISTS sbom_license_expanded (
    sbom_id UUID NOT NULL,
    license_id UUID NOT NULL,
    expanded_license_id UUID NOT NULL,
    PRIMARY KEY (sbom_id, license_id),
    FOREIGN KEY (sbom_id) REFERENCES sbom(sbom_id) ON DELETE CASCADE,
    FOREIGN KEY (license_id) REFERENCES license(id) ON DELETE CASCADE,
    FOREIGN KEY (expanded_license_id) REFERENCES expanded_license(id) ON DELETE CASCADE
);

-- Index for reverse lookups (expanded_license_id → sbom_license_expanded)
CREATE INDEX IF NOT EXISTS idx_sle_expanded_license_id
ON sbom_license_expanded (expanded_license_id);

-- Replace regex-based expansion with faster string replace.
-- SPDX expressions have well-defined delimiters (space, parentheses, +), so we can
-- use replace() with all valid boundary combinations instead of regexp_replace()
-- with dynamically compiled patterns.
CREATE OR REPLACE FUNCTION expand_license_expression_with_mappings(
    license_text TEXT,
    license_mappings license_mapping[]
) RETURNS TEXT AS $$
DECLARE
    result_text TEXT;
    mapping license_mapping;
BEGIN
    IF license_text IS NULL
       OR POSITION('LicenseRef-' IN license_text) = 0
       OR license_mappings IS NULL
       OR array_length(license_mappings, 1) IS NULL THEN
        RETURN license_text;
    END IF;

    -- Sentinel spaces handle start/end-of-string boundaries uniformly
    result_text := ' ' || license_text || ' ';

    FOREACH mapping IN ARRAY license_mappings
    LOOP
        IF POSITION('LicenseRef-' IN result_text) = 0 THEN
            EXIT;
        END IF;

        -- Replace whole-token matches using all valid SPDX boundary pairs.
        -- Before: space or '('  |  After: space, ')', or '+'
        result_text := replace(result_text, ' ' || mapping.license_id || ' ',  ' ' || mapping.name || ' ');
        result_text := replace(result_text, ' ' || mapping.license_id || ')',  ' ' || mapping.name || ')');
        result_text := replace(result_text, ' ' || mapping.license_id || '+',  ' ' || mapping.name || '+');
        result_text := replace(result_text, '(' || mapping.license_id || ' ',  '(' || mapping.name || ' ');
        result_text := replace(result_text, '(' || mapping.license_id || ')',  '(' || mapping.name || ')');
        result_text := replace(result_text, '(' || mapping.license_id || '+',  '(' || mapping.name || '+');
    END LOOP;

    RETURN substring(result_text FROM 2 FOR length(result_text) - 2);
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;

-- Update planner statistics before backfill for accurate cost estimates
ANALYZE sbom_package_license;
ANALYZE licensing_infos;
ANALYZE sbom_license_expanded;
ANALYZE license;

-- Backfill Step 1: Insert unique expanded texts into dictionary
-- Split into two passes to avoid the expensive LEFT JOIN with licensing_infos
-- and PL/pgSQL function calls for the majority of rows that don't contain LicenseRef-.

-- Pass 1a: Texts WITHOUT LicenseRef- (majority, no expansion needed)
-- Skips the LEFT JOIN with licensing_infos and the function call entirely.
-- Subquery is flattened so the planner can push the anti-join before the sort.
INSERT INTO expanded_license (expanded_text)
SELECT DISTINCT l.text
FROM sbom_package_license spl
JOIN license l ON l.id = spl.license_id
WHERE l.text NOT LIKE '%LicenseRef-%'
  AND NOT EXISTS (
      SELECT 1 FROM sbom_license_expanded sle
      WHERE sle.sbom_id = spl.sbom_id
  )
ON CONFLICT (text_hash) DO NOTHING;

-- Pass 1b: Texts WITH LicenseRef- (minority, needs expansion via license mappings)
INSERT INTO expanded_license (expanded_text)
SELECT DISTINCT expand_license_expression_with_mappings(
    l.text,
    COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
)
FROM sbom_package_license spl
JOIN license l ON l.id = spl.license_id
LEFT JOIN (
    SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
    FROM licensing_infos
    GROUP BY sbom_id
) lim ON lim.sbom_id = spl.sbom_id
WHERE l.text LIKE '%LicenseRef-%'
  AND NOT EXISTS (
      SELECT 1 FROM sbom_license_expanded sle
      WHERE sle.sbom_id = spl.sbom_id
  )
ON CONFLICT (text_hash) DO NOTHING;

-- Backfill Step 2: Insert junction rows
-- Split into two passes matching Step 1's LicenseRef- split.

-- Pass 2a: Texts WITHOUT LicenseRef- (direct hash join, no function call)
INSERT INTO sbom_license_expanded (sbom_id, license_id, expanded_license_id)
SELECT DISTINCT spl.sbom_id, spl.license_id, el.id
FROM sbom_package_license spl
JOIN license l ON l.id = spl.license_id
JOIN expanded_license el ON el.text_hash = md5(l.text)
WHERE l.text NOT LIKE '%LicenseRef-%'
  AND NOT EXISTS (
      SELECT 1 FROM sbom_license_expanded sle
      WHERE sle.sbom_id = spl.sbom_id AND sle.license_id = spl.license_id
  )
ON CONFLICT (sbom_id, license_id) DO UPDATE
SET expanded_license_id = EXCLUDED.expanded_license_id;

-- Pass 2b: Texts WITH LicenseRef- (CTE calls expansion function once per pair)
-- MATERIALIZED prevents PostgreSQL from inlining the CTE, which would cause
-- expand_license_expression_with_mappings() to be evaluated twice per row
-- (once for DISTINCT, once for the md5 join with expanded_license).
WITH license_expansions AS MATERIALIZED (
    SELECT DISTINCT
        spl.sbom_id,
        spl.license_id,
        expand_license_expression_with_mappings(
            l.text,
            COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
        ) AS expanded_text
    FROM sbom_package_license spl
    JOIN license l ON l.id = spl.license_id
    LEFT JOIN (
        SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
        FROM licensing_infos
        GROUP BY sbom_id
    ) lim ON lim.sbom_id = spl.sbom_id
    WHERE l.text LIKE '%LicenseRef-%'
      AND NOT EXISTS (
          SELECT 1 FROM sbom_license_expanded sle
          WHERE sle.sbom_id = spl.sbom_id AND sle.license_id = spl.license_id
      )
)
INSERT INTO sbom_license_expanded (sbom_id, license_id, expanded_license_id)
SELECT ne.sbom_id, ne.license_id, el.id
FROM license_expansions ne
JOIN expanded_license el ON el.text_hash = md5(ne.expanded_text)
ON CONFLICT (sbom_id, license_id) DO UPDATE
SET expanded_license_id = EXCLUDED.expanded_license_id;

-- Drop old SQL functions (no longer needed after backfill)
DROP FUNCTION IF EXISTS case_license_text_sbom_id(TEXT, UUID);
DROP FUNCTION IF EXISTS expand_license_expression(TEXT, UUID);

-- Keep expand_license_expression_with_mappings() for ingestion-time use
