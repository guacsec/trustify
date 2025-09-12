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
        SELECT
            "advisory"."id" AS "advisory$id",
            "advisory"."identifier" AS "advisory$identifier",
            "advisory"."version" AS "advisory$version",
            "advisory"."document_id" AS "advisory$document_id",
            "advisory"."deprecated" AS "advisory$deprecated",
            "advisory"."issuer_id" AS "advisory$issuer_id",
            "advisory"."published" AS "advisory$published",
            "advisory"."modified" AS "advisory$modified",
            "advisory"."withdrawn" AS "advisory$withdrawn",
            "advisory"."title" AS "advisory$title",
            "advisory"."labels" AS "advisory$labels",
            "advisory"."source_document_id" AS "advisory$source_document_id",
            "advisory_vulnerability"."advisory_id" AS "advisory_vulnerability$advisory_id",
            "advisory_vulnerability"."vulnerability_id" AS "advisory_vulnerability$vulnerability_id",
            "advisory_vulnerability"."title" AS "advisory_vulnerability$title",
            "advisory_vulnerability"."summary" AS "advisory_vulnerability$summary",
            "advisory_vulnerability"."description" AS "advisory_vulnerability$description",
            "advisory_vulnerability"."reserved_date" AS "advisory_vulnerability$reserved_date",
            "advisory_vulnerability"."discovery_date" AS "advisory_vulnerability$discovery_date",
            "advisory_vulnerability"."release_date" AS "advisory_vulnerability$release_date",
            "advisory_vulnerability"."cwes" AS "advisory_vulnerability$cwes",
            "vulnerability"."id" AS "vulnerability$id",
            "vulnerability"."title" AS "vulnerability$title",
            "vulnerability"."reserved" AS "vulnerability$reserved",
            "vulnerability"."published" AS "vulnerability$published",
            "vulnerability"."modified" AS "vulnerability$modified",
            "vulnerability"."withdrawn" AS "vulnerability$withdrawn",
            "vulnerability"."cwes" AS "vulnerability$cwes",
            "qualified_purl"."id" AS "qualified_purl$id",
            "qualified_purl"."versioned_purl_id" AS "qualified_purl$versioned_purl_id",
            "qualified_purl"."qualifiers" AS "qualified_purl$qualifiers",
            "qualified_purl"."purl" AS "qualified_purl$purl",
            "sbom_package"."sbom_id" AS "sbom_package$sbom_id",
            "sbom_package"."node_id" AS "sbom_package$node_id",
            "sbom_package"."version" AS "sbom_package$version",
            "sbom_node"."sbom_id" AS "sbom_node$sbom_id",
            "sbom_node"."node_id" AS "sbom_node$node_id",
            "sbom_node"."name" AS "sbom_node$name",
            "status"."id" AS "status$id",
            "status"."slug" AS "status$slug",
            "status"."name" AS "status$name",
            "status"."description" AS "status$description",
            "cpe"."id" AS "cpe$id",
            "cpe"."part" AS "cpe$part",
            "cpe"."vendor" AS "cpe$vendor",
            "cpe"."product" AS "cpe$product",
            "cpe"."version" AS "cpe$version",
            "cpe"."update" AS "cpe$update",
            "cpe"."edition" AS "cpe$edition",
            "cpe"."language" AS "cpe$language",
            "organization"."id" AS "organization$id",
            "organization"."name" AS "organization$name",
            "organization"."cpe_key" AS "organization$cpe_key",
            "organization"."website" AS "organization$website"
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
