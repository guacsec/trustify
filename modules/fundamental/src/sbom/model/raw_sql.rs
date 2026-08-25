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
            FROM sbom_package_purl_ref spr
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

pub fn cpe_advisory_info_sql() -> String {
    r#"
        WITH
        -- Package-level CPEs referenced by this SBOM, joined back to the
        -- owning package for its purl and (fallback) version.
        sbom_cpe_pkgs AS (
            SELECT
                scr.sbom_id,
                scr.node_id,
                c.vendor,
                c.product,
                c.part,
                COALESCE(NULLIF(c.version, '*'), sp.version) AS version,
                spr.qualified_purl_id
            FROM sbom_package_cpe_ref scr
            JOIN cpe c ON scr.cpe_id = c.id
            JOIN sbom_package sp ON sp.sbom_id = scr.sbom_id AND sp.node_id = scr.node_id
            LEFT JOIN sbom_package_purl_ref spr ON spr.sbom_id = scr.sbom_id AND spr.node_id = scr.node_id
            WHERE scr.sbom_id = $1
        ),

        -- CPE-status matches: identity by vendor+product (application CPEs
        -- only), affected version range checked via version_matches().
        cpe_status_matches AS (
            SELECT DISTINCT
                cs.advisory_id,
                cs.vulnerability_id,
                cs.status_id,
                cs.context_cpe_id,
                p.qualified_purl_id,
                p.sbom_id,
                p.node_id
            FROM cpe_status cs
            JOIN cpe sc ON cs.cpe_id = sc.id
            JOIN sbom_cpe_pkgs p
                ON p.vendor = sc.vendor
               AND p.product = sc.product
               AND sc.part = 'a'
               AND p.part = 'a'
            JOIN version_range vr ON cs.version_range_id = vr.id
            WHERE version_matches(p.version, vr.*)
        )

        -- Final query joins to get all required fields (mirrors the tail of
        -- product_advisory_info_sql).
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
        FROM cpe_status_matches m
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
