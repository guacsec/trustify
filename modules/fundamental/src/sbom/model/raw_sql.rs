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
    format!(
        r#"
        SELECT DISTINCT
            "advisory"."id" AS "advisory_id",
            "advisory_vulnerability"."advisory_id" AS "av_advisory_id",
            "advisory_vulnerability"."vulnerability_id" AS "av_vulnerability_id",
            "vulnerability"."id" AS "vulnerability_id",
            "qualified_purl"."id" AS "qualified_purl_id",
            "sbom_package"."sbom_id" AS "sbom_id",
            "sbom_package"."node_id" AS "node_id",
            "status"."id" AS "status_id",
            "cpe"."id" AS "cpe_id",
            "organization"."id" AS "organization_id"
        FROM product_status
        JOIN cpe ON product_status.context_cpe_id = cpe.id

        -- now find matching purls in these statuses
        JOIN base_purl ON product_status.package = base_purl.name OR product_status.package LIKE CONCAT(base_purl.namespace, '/', base_purl.name)
        JOIN "versioned_purl" ON "versioned_purl"."base_purl_id" = "base_purl"."id"
        JOIN "qualified_purl" ON "qualified_purl"."versioned_purl_id" = "versioned_purl"."id"
        join sbom_package_purl_ref ON sbom_package_purl_ref.qualified_purl_id = qualified_purl.id AND sbom_package_purl_ref.sbom_id = $1
        JOIN sbom_package on sbom_package.sbom_id = sbom_package_purl_ref.sbom_id AND sbom_package.node_id = sbom_package_purl_ref.node_id
        JOIN sbom_node on sbom_node.sbom_id = sbom_package_purl_ref.sbom_id AND sbom_node.node_id = sbom_package_purl_ref.node_id

        -- get basic status info
        JOIN "status" ON "product_status"."status_id" = "status"."id"
        JOIN "advisory" ON "product_status"."advisory_id" = "advisory"."id"
        LEFT JOIN "organization" ON "advisory"."issuer_id" = "organization"."id"
        JOIN "advisory_vulnerability" ON "product_status"."advisory_id" = "advisory_vulnerability"."advisory_id"
        AND "product_status"."vulnerability_id" = "advisory_vulnerability"."vulnerability_id"
        JOIN "vulnerability" ON "advisory_vulnerability"."vulnerability_id" = "vulnerability"."id"
        WHERE
        ($2::text[] = ARRAY[]::text[] OR "status"."slug" = ANY($2::text[]))
        AND {CONTEXT_CPE_FILTER_SQL}
        "#
    )
}
