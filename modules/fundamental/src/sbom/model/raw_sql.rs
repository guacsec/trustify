/// This constant is a SQL subquery that filters the context_cpe_id
/// based on the given sbom_id. It reads from the materialized
/// sbom_describing_cpe table instead of computing the join at query time.
/// The generalized CPE logic expands matches to include CPEs without edition
/// and with major-version-only matching.
pub const CONTEXT_CPE_FILTER_SQL: &str = r#"
(
    context_cpe_id IS NULL OR
    context_cpe_id IN (
        WITH filtered_cpes AS (
            SELECT cpe.*
            FROM sbom_describing_cpe sdc
            JOIN cpe ON sdc.cpe_id = cpe.id
            WHERE sdc.sbom_id = $1
        ),
        generalized_cpes AS (
            SELECT *
            FROM cpe
            WHERE (edition IS NULL OR edition = '*')
              AND (vendor, product, version) IN (
                  SELECT vendor, product, split_part(version, '.', 1)
                  FROM filtered_cpes
              )
        )
        SELECT id FROM filtered_cpes
        UNION
        SELECT id FROM generalized_cpes
    ) OR (
        SELECT cpe_id
        FROM sbom_describing_cpe
        WHERE sbom_id = $1
        LIMIT 1
    ) IS NULL
)
"#;

/// Returns SQL that counts affected vulnerabilities grouped by severity for
/// multiple SBOMs in a single query. Combines both PURL-based matching (via
/// `purl_status` + `version_matches()`) and CPE-based matching (via
/// `product_status` + package name matching). Takes `$1 = Uuid[]` and returns
/// `(sbom_id, severity, count)` rows.
///
/// Uses a shared `sbom_purl_info` CTE (referenced 3x) that PostgreSQL
/// auto-materializes, acting as a barrier that prevents the planner from
/// inlining the SBOM's package set and scanning the full `versioned_purl`
/// table. The advisory filter is deferred to a separate CTE so the
/// expensive `version_matches()` narrows the set before any advisory
/// lookups.
pub fn batch_severity_counts_sql() -> &'static str {
    r#"
    WITH
    -- Unnest the input array of SBOM IDs
    input_sboms AS (
        SELECT unnest($1::uuid[]) AS sbom_id
    ),

    -- Shared CTE: SBOM package info including version, base_purl_id,
    -- and name/namespace. Referenced 3x so PostgreSQL auto-materializes
    -- it, preventing the planner from inlining and scanning the full
    -- versioned_purl table. Including base_purl here nudges the planner
    -- to hash the small side (20k rows) instead of the large one (1.6M).
    sbom_purl_info AS (
        SELECT
            spr.sbom_id,
            vp.version,
            vp.base_purl_id,
            bp.name,
            bp.namespace
        FROM input_sboms i
        JOIN sbom_node_purl_ref spr ON spr.sbom_id = i.sbom_id
        JOIN qualified_purl qp ON spr.qualified_purl_id = qp.id
        JOIN versioned_purl vp ON qp.versioned_purl_id = vp.id
        JOIN base_purl bp ON vp.base_purl_id = bp.id
    ),

    -- CPE-based matching: per-SBOM allowed CPE IDs with generalized matching
    sbom_cpes AS (
        SELECT i.sbom_id, cpe.*
        FROM input_sboms i
        JOIN sbom_describing_cpe sdc ON sdc.sbom_id = i.sbom_id
        JOIN cpe ON sdc.cpe_id = cpe.id
    ),
    sbom_generalized_cpes AS (
        SELECT sc.sbom_id, c.*
        FROM sbom_cpes sc
        JOIN cpe c ON c.vendor = sc.vendor
            AND c.product = sc.product
            AND c.version = split_part(sc.version, '.', 1)
            AND (c.edition IS NULL OR c.edition = '*')
    ),
    sbom_allowed_cpes AS (
        SELECT sbom_id, id AS cpe_id FROM sbom_cpes
        UNION
        SELECT sbom_id, id AS cpe_id FROM sbom_generalized_cpes
    ),
    sbom_has_cpes AS (
        SELECT DISTINCT sbom_id FROM sbom_cpes
    ),

    -- PURL-based matching: version_matches called only for SBOM's packages,
    -- advisory filter deferred to avoid unnecessary lookups.
    purl_version_matches AS (
        SELECT DISTINCT
            sp.sbom_id,
            pst.advisory_id,
            pst.vulnerability_id
        FROM sbom_purl_info sp
        JOIN purl_status pst ON pst.base_purl_id = sp.base_purl_id
        JOIN version_range vr ON pst.version_range_id = vr.id
        JOIN status ON pst.status_id = status.id
        WHERE status.slug = 'affected'
          AND version_matches(sp.version, vr.*)
          AND (
              pst.context_cpe_id IS NULL
              OR pst.context_cpe_id IN (SELECT cpe_id FROM sbom_allowed_cpes sac WHERE sac.sbom_id = sp.sbom_id)
              OR sp.sbom_id NOT IN (SELECT sbom_id FROM sbom_has_cpes)
          )
    ),
    purl_matches AS (
        SELECT pm.sbom_id, pm.advisory_id, pm.vulnerability_id
        FROM purl_version_matches pm
        WHERE NOT EXISTS (
            SELECT 1 FROM advisory a
            WHERE a.id = pm.advisory_id AND a.deprecated
        )
    ),

    -- CPE product_status matches by name
    cpe_matches_name AS (
        SELECT DISTINCT
            sp.sbom_id,
            ps.advisory_id,
            ps.vulnerability_id
        FROM product_status ps
        JOIN sbom_purl_info sp ON ps.package = sp.name
        JOIN status ON ps.status_id = status.id
        JOIN advisory ON ps.advisory_id = advisory.id
        WHERE status.slug = 'affected'
          AND advisory.deprecated = false
          AND (
              ps.context_cpe_id IS NULL
              OR ps.context_cpe_id IN (SELECT cpe_id FROM sbom_allowed_cpes sac WHERE sac.sbom_id = sp.sbom_id)
              OR sp.sbom_id NOT IN (SELECT sbom_id FROM sbom_has_cpes)
          )
    ),

    -- CPE product_status matches by namespace/name
    cpe_matches_ns AS (
        SELECT DISTINCT
            sp.sbom_id,
            ps.advisory_id,
            ps.vulnerability_id
        FROM product_status ps
        JOIN sbom_purl_info sp ON ps.package = CONCAT(sp.namespace, '/', sp.name)
        JOIN status ON ps.status_id = status.id
        JOIN advisory ON ps.advisory_id = advisory.id
        WHERE sp.namespace IS NOT NULL
          AND status.slug = 'affected'
          AND advisory.deprecated = false
          AND (
              ps.context_cpe_id IS NULL
              OR ps.context_cpe_id IN (SELECT cpe_id FROM sbom_allowed_cpes sac WHERE sac.sbom_id = sp.sbom_id)
              OR sp.sbom_id NOT IN (SELECT sbom_id FROM sbom_has_cpes)
          )
    ),

    -- Union all matches
    all_affected AS (
        SELECT * FROM purl_matches
        UNION
        SELECT * FROM cpe_matches_name
        UNION
        SELECT * FROM cpe_matches_ns
    ),

    -- Pick the highest severity per (sbom, vulnerability), collapsing
    -- across advisories and CVSS versions into one row per unique vuln.
    -- Unknown (no CVSS score) is treated as the lowest severity so that
    -- a real score from any advisory always wins.
    scored AS (
        SELECT DISTINCT ON (a.sbom_id, a.vulnerability_id)
            a.sbom_id,
            COALESCE(avs.severity::text, 'unknown') AS severity
        FROM all_affected a
        LEFT JOIN advisory_vulnerability_score avs
            ON avs.advisory_id = a.advisory_id
            AND avs.vulnerability_id = a.vulnerability_id
        ORDER BY a.sbom_id, a.vulnerability_id,
            CASE avs.severity::text
                WHEN 'critical' THEN 5
                WHEN 'high' THEN 4
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 2
                WHEN 'none' THEN 1
                ELSE 0
            END DESC
    )

    SELECT
        sbom_id,
        severity,
        COUNT(*) AS count
    FROM scored
    GROUP BY sbom_id, severity
    "#
}

pub fn product_advisory_info_sql() -> String {
    r#"
        WITH
        -- Read describing CPEs from the materialized table
        filtered_cpes AS (
            SELECT cpe.*
            FROM sbom_describing_cpe sdc
            JOIN cpe ON sdc.cpe_id = cpe.id
            WHERE sdc.sbom_id = $1
        ),
        generalized_cpes AS (
            SELECT *
            FROM cpe
            WHERE (edition IS NULL OR edition = '*')
              AND (vendor, product, version) IN (
                  SELECT vendor, product, split_part(version, '.', 1)
                  FROM filtered_cpes
              )
        ),
        allowed_cpe_ids AS (
            SELECT id FROM filtered_cpes
            UNION
            SELECT id FROM generalized_cpes
        ),

        -- Pre-filter SBOM packages for this specific SBOM to avoid repeated scans
        sbom_purls AS (
            SELECT
                qp.id as qualified_purl_id,
                bp.name,
                bp.namespace,
                spr.sbom_id,
                spr.node_id
            FROM sbom_node_purl_ref spr
            JOIN qualified_purl qp ON spr.qualified_purl_id = qp.id
            JOIN versioned_purl vp ON qp.versioned_purl_id = vp.id
            JOIN base_purl bp ON vp.base_purl_id = bp.id
            WHERE spr.sbom_id = $1
        ),

        -- Split OR condition into UNION to enable index usage
        -- Match 1: Simple name equality (most common case)
        product_status_matches_name AS (
            SELECT DISTINCT
                ps.id as product_status_id,
                ps.advisory_id,
                ps.vulnerability_id,
                ps.status_id,
                ps.context_cpe_id,
                sp.qualified_purl_id,
                sp.sbom_id,
                sp.node_id
            FROM product_status ps
            JOIN sbom_purls sp ON ps.package = sp.name
            WHERE (ps.context_cpe_id IS NULL
                   OR ps.context_cpe_id IN (SELECT id FROM allowed_cpe_ids)
                   OR NOT EXISTS (SELECT 1 FROM filtered_cpes LIMIT 1))
        ),

        -- Match 2: Namespace/name concatenation (handles scoped packages like npm, maven)
        product_status_matches_namespace AS (
            SELECT DISTINCT
                ps.id as product_status_id,
                ps.advisory_id,
                ps.vulnerability_id,
                ps.status_id,
                ps.context_cpe_id,
                sp.qualified_purl_id,
                sp.sbom_id,
                sp.node_id
            FROM product_status ps
            JOIN sbom_purls sp ON ps.package = CONCAT(sp.namespace, '/', sp.name)
            WHERE sp.namespace IS NOT NULL
              AND (ps.context_cpe_id IS NULL
                   OR ps.context_cpe_id IN (SELECT id FROM allowed_cpe_ids)
                   OR NOT EXISTS (SELECT 1 FROM filtered_cpes LIMIT 1))
        ),

        -- Union the two match types to eliminate OR in JOIN
        all_matches AS (
            SELECT * FROM product_status_matches_name
            UNION
            SELECT * FROM product_status_matches_namespace
        )

        -- Final query joins to get all required fields
        SELECT DISTINCT
            "advisory"."id" AS "advisory_id",
            "advisory_vulnerability"."advisory_id" AS "av_advisory_id",
            "advisory_vulnerability"."vulnerability_id" AS "av_vulnerability_id",
            "vulnerability"."id" AS "vulnerability_id",
            m.qualified_purl_id AS "qualified_purl_id",
            m.sbom_id AS "sbom_id",
            m.node_id AS "node_id",
            "status"."id" AS "status_id",
            "cpe"."id" AS "cpe_id",
            "organization"."id" AS "organization_id"
        FROM all_matches m
        JOIN sbom_package ON sbom_package.sbom_id = m.sbom_id AND sbom_package.node_id = m.node_id
        JOIN sbom_node ON sbom_node.sbom_id = m.sbom_id AND sbom_node.node_id = m.node_id
        JOIN "status" ON m.status_id = "status"."id"
        JOIN "advisory" ON m.advisory_id = "advisory"."id"
        LEFT JOIN "organization" ON "advisory"."issuer_id" = "organization"."id"
        JOIN "advisory_vulnerability" ON m.advisory_id = "advisory_vulnerability"."advisory_id"
            AND m.vulnerability_id = "advisory_vulnerability"."vulnerability_id"
        JOIN "vulnerability" ON "advisory_vulnerability"."vulnerability_id" = "vulnerability"."id"
        LEFT JOIN "cpe" ON m.context_cpe_id = "cpe"."id"
        WHERE ($2::text[] = ARRAY[]::text[] OR "status"."slug" = ANY($2::text[]))
          AND "advisory"."deprecated" = false
        "#
    .to_string()
}
