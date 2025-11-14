/// This constant is a SQL subquery that filters the context_cpe_id
/// based on the given sbom_id. It checks if the context_cpe_id is null
/// or if it is in the list of CPEs that are related to the packages
/// that describes the SBOM. The additional logic allows us to find
/// superset of generalized CPEs that don't include subfields like edition
/// and find "stream" releases based on the major version.
pub const CONTEXT_CPE_FILTER_SQL: &str = r#"
(
    context_cpe_id IS NULL OR
    context_cpe_id IN (
        WITH related_nodes AS (
            SELECT DISTINCT right_node_id
            FROM package_relates_to_package
            WHERE sbom_id = $1
              AND relationship = 13
        ),
        sbom_cpes AS (
            SELECT cpe_id, node_id
            FROM sbom_package_cpe_ref
            WHERE sbom_id = $1
              AND node_id IN (SELECT right_node_id FROM related_nodes)
        ),
        filtered_cpes AS (
            SELECT cpe.*
            FROM sbom_cpes spcr
            JOIN cpe ON spcr.cpe_id = cpe.id
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
        FROM sbom_package_cpe_ref
        WHERE sbom_id = $1
        AND node_id IN (
            SELECT DISTINCT right_node_id
            FROM package_relates_to_package
            WHERE sbom_id = $1
            AND relationship = 13
        )
        LIMIT 1
    ) IS NULL
)
"#;

pub fn product_advisory_info_sql() -> String {
    r#"
        WITH
        -- Pre-compute CPE context filter once instead of in WHERE clause
        related_nodes AS (
            SELECT DISTINCT right_node_id
            FROM package_relates_to_package
            WHERE sbom_id = $1
              AND relationship = 13
        ),
        sbom_cpes AS (
            SELECT cpe_id, node_id
            FROM sbom_package_cpe_ref
            WHERE sbom_id = $1
              AND node_id IN (SELECT right_node_id FROM related_nodes)
        ),
        filtered_cpes AS (
            SELECT cpe.*
            FROM sbom_cpes spcr
            JOIN cpe ON spcr.cpe_id = cpe.id
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
                   OR NOT EXISTS (SELECT 1 FROM sbom_cpes LIMIT 1))
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
                   OR NOT EXISTS (SELECT 1 FROM sbom_cpes LIMIT 1))
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
