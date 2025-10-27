WITH
    -- Input: Array of qualified_purl IDs from the deleted SBOM (captured before CASCADE)
    sbom_qualified_purls AS (
        SELECT unnest($1) as id
    ),
    -- Find orphaned qualified_purls (not in any remaining SBOM, not advisory-referenced)
    orphaned_qualified AS (
        SELECT sq.id
        FROM sbom_qualified_purls sq
        WHERE NOT EXISTS (
            -- Check if still referenced by other SBOMs
            -- The deleted SBOM's references are already removed by previously executed CASCADE
            SELECT 1 FROM sbom_package_purl_ref sppr
            WHERE sppr.qualified_purl_id = sq.id
        )
        AND NOT EXISTS (
            -- Check if base_purl is in purl_status (advisory reference)
            -- Conservative: keeps ALL versions of a package if base_purl has purl_status
            SELECT 1 FROM qualified_purl qp
            JOIN versioned_purl vp ON vp.id = qp.versioned_purl_id
            JOIN purl_status ps ON ps.base_purl_id = vp.base_purl_id
            WHERE qp.id = sq.id
        )
    ),
    -- Find orphaned versioned_purls (no qualified_purls reference them after qualified cleanup)
    orphaned_versioned AS (
        SELECT DISTINCT vp.id
        FROM versioned_purl vp
        WHERE EXISTS (
            -- At least one qualified_purl from orphaned set uses this versioned_purl
            SELECT 1 FROM orphaned_qualified oq
            JOIN qualified_purl qp ON qp.id = oq.id
            WHERE qp.versioned_purl_id = vp.id
        )
        AND NOT EXISTS (
            -- No other qualified_purls reference this versioned_purl (besides orphaned ones)
            SELECT 1 FROM qualified_purl qp2
            WHERE qp2.versioned_purl_id = vp.id
            AND qp2.id NOT IN (SELECT id FROM orphaned_qualified)
        )
        AND NOT EXISTS (
            -- Base_purl not in purl_status (advisory reference)
            SELECT 1 FROM purl_status ps
            WHERE ps.base_purl_id = vp.base_purl_id
        )
    ),
    -- Find orphaned base_purls (no versioned_purls reference them after versioned cleanup)
    orphaned_base AS (
        SELECT DISTINCT bp.id
        FROM base_purl bp
        WHERE EXISTS (
            -- At least one versioned_purl from orphaned set uses this base_purl
            SELECT 1 FROM orphaned_versioned ov
            JOIN versioned_purl vp ON vp.id = ov.id
            WHERE vp.base_purl_id = bp.id
        )
        AND NOT EXISTS (
            -- No other versioned_purls reference this base_purl (besides orphaned ones)
            SELECT 1 FROM versioned_purl vp2
            WHERE vp2.base_purl_id = bp.id
            AND vp2.id NOT IN (SELECT id FROM orphaned_versioned)
        )
        AND NOT EXISTS (
            -- Base_purl not in purl_status (advisory reference)
            SELECT 1 FROM purl_status ps
            WHERE ps.base_purl_id = bp.id
        )
    ),
    -- DELETE operations: remove orphaned purls in correct dependency order
    deleted_qualified AS (
        DELETE FROM qualified_purl
        WHERE id IN (SELECT id FROM orphaned_qualified)
        RETURNING 'qualified_purl' as table_name, id
    ),
    deleted_versioned AS (
        DELETE FROM versioned_purl
        WHERE id IN (SELECT id FROM orphaned_versioned)
        RETURNING 'versioned_purl' as table_name, id
    ),
    deleted_base AS (
        DELETE FROM base_purl
        WHERE id IN (SELECT id FROM orphaned_base)
        RETURNING 'base_purl' as table_name, id
    ),
    -- Combine all deleted records for reporting
    deleted_records AS (
        SELECT * FROM deleted_qualified
        UNION ALL
        SELECT * FROM deleted_versioned
        UNION ALL
        SELECT * FROM deleted_base
    )
SELECT * FROM deleted_records;
