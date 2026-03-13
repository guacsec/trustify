-- Create dictionary table for unique expanded license texts
CREATE TABLE IF NOT EXISTS expanded_license (
    id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    expanded_text TEXT NOT NULL
);

-- MD5 hash index for deduplication (handles long texts >2.7KB that exceed B-tree limits)
CREATE UNIQUE INDEX IF NOT EXISTS idx_expanded_license_text_hash
ON expanded_license (md5(expanded_text));

-- Create junction table mapping (sbom_id, license_id) → expanded_license_id
CREATE TABLE IF NOT EXISTS sbom_license_expanded (
    sbom_id UUID NOT NULL,
    license_id UUID NOT NULL,
    expanded_license_id INTEGER NOT NULL,
    PRIMARY KEY (sbom_id, license_id),
    FOREIGN KEY (expanded_license_id) REFERENCES expanded_license(id) ON DELETE CASCADE
);

-- Index for reverse lookups (expanded_license_id → sbom_license_expanded)
CREATE INDEX IF NOT EXISTS idx_sle_expanded_license_id
ON sbom_license_expanded (expanded_license_id);

-- Backfill Step 1: Insert unique expanded texts into dictionary
-- Pre-deduplicate by (text, sbom_id) to avoid millions of redundant function calls
INSERT INTO expanded_license (expanded_text)
SELECT DISTINCT expand_license_expression_with_mappings(
    uls.text,
    COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
)
FROM (
    SELECT DISTINCT l.text, spl.sbom_id
    FROM sbom_package_license spl
    JOIN license l ON l.id = spl.license_id
) uls
LEFT JOIN (
    SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
    FROM licensing_infos
    GROUP BY sbom_id
) lim ON lim.sbom_id = uls.sbom_id
WHERE NOT EXISTS (
    SELECT 1 FROM sbom_license_expanded sle
    WHERE sle.sbom_id = uls.sbom_id
)
ON CONFLICT (md5(expanded_text)) DO NOTHING;

-- Backfill Step 2: Insert junction rows
INSERT INTO sbom_license_expanded (sbom_id, license_id, expanded_license_id)
SELECT DISTINCT spl.sbom_id, spl.license_id, el.id
FROM sbom_package_license spl
JOIN license l ON l.id = spl.license_id
LEFT JOIN (
    SELECT array_agg(ROW(license_id, name)::license_mapping) AS license_mapping, sbom_id
    FROM licensing_infos
    GROUP BY sbom_id
) lim ON lim.sbom_id = spl.sbom_id
JOIN expanded_license el ON md5(el.expanded_text) = md5(
    expand_license_expression_with_mappings(
        l.text,
        COALESCE(lim.license_mapping, ARRAY[]::license_mapping[])
    )
)
WHERE NOT EXISTS (
    SELECT 1 FROM sbom_license_expanded sle
    WHERE sle.sbom_id = spl.sbom_id AND sle.license_id = spl.license_id
)
ON CONFLICT (sbom_id, license_id) DO UPDATE
SET expanded_license_id = EXCLUDED.expanded_license_id;

-- Drop old SQL functions (no longer needed after backfill)
DROP FUNCTION IF EXISTS case_license_text_sbom_id(TEXT, UUID);
DROP FUNCTION IF EXISTS expand_license_expression(TEXT, UUID);

-- Keep expand_license_expression_with_mappings() for ingestion-time use
