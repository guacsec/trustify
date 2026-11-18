//! Main-only assertion identity support. Keep this separate from the release's
//! CPE/RPM applicability rules; it needs neither extraction nor verdict snapshots.

use sea_orm::ActiveEnum;
use trustify_entity::relationship::Relationship;

pub(crate) enum PackageNodes<'a> {
    /// Node-level results must not borrow evidence from another occurrence.
    Node(&'a str),
    /// Aggregate results need only one matching occurrence of the qualified PURL.
    AnyOccurrence(&'a str),
}

/// Do not look for extra evidence on unscoped assertions or ones already
/// checked by the caller's legacy CPE predicate.
pub(crate) fn require_evidence(context: &str, assertion: &str, evidence: &str) -> String {
    format!(
        "(CASE WHEN {context} IS NOT NULL OR {assertion} IS NULL THEN true ELSE {evidence} END)"
    )
}

pub(crate) fn filter(
    context: &str,
    assertion: &str,
    purl: &str,
    bound: &str,
    sbom: &str,
    package: PackageNodes<'_>,
) -> String {
    require_evidence(
        context,
        assertion,
        &evidence(assertion, purl, bound, sbom, package),
    )
}

/// Match CPEs using the same RPM/root rules (without the missing-root fallback),
/// or other product identifiers on the package or an SBOM-described product.
pub(crate) fn evidence(
    assertion: &str,
    purl: &str,
    bound: &str,
    sbom: &str,
    package: PackageNodes<'_>,
) -> String {
    let (explicit, _) = super::describing("scope_identifier.cpe_id", sbom);
    let cpe = super::filter(
        "scope_identifier.cpe_id",
        purl,
        bound,
        &explicit,
        "false",
        &super::attribute_proof(&format!("proof_d.sbom_id = {sbom}")),
    );
    let package = match package {
        PackageNodes::Node(node) => format!("SELECT {node} AS node_id"),
        PackageNodes::AnyOccurrence(qualified_purl) => format!(
            "SELECT node_id FROM sbom_node_purl_ref
             WHERE sbom_id = {sbom} AND qualified_purl_id = {qualified_purl}"
        ),
    };
    // The SBOM root node is the document; follow its indexed Describes edges.
    // Duplicates do not matter to EXISTS, so UNION ALL avoids a sort/hash.
    let nodes = format!(
        r#"{package}
           UNION ALL
           SELECT describes.right_node_id
           FROM sbom document
           JOIN package_relates_to_package describes
             ON describes.sbom_id = document.sbom_id AND describes.left_node_id = document.node_id
           WHERE document.sbom_id = {sbom} AND describes.relationship = {describes}"#,
        describes = Relationship::Describes.to_value(),
    );
    // CSAF globs use * and ?, not SQL's % and _. Escape SQL metacharacters first.
    let pattern = r#"replace(replace(replace(replace(replace(scope_identifier.value,
        E'\\', E'\\\\'), '%', E'\\%'), '_', E'\\_'), '*', '%'), '?', '_')"#;
    format!(
        r#"EXISTS (
            SELECT 1 FROM assertion_context_identifier scope_identifier
            WHERE scope_identifier.context_id = {assertion}
              AND CASE WHEN scope_identifier.kind = 'cpe'
                THEN scope_identifier.cpe_id IS NOT NULL AND {cpe}
                ELSE EXISTS (
                    SELECT 1 FROM ({nodes}) scope_node
                    WHERE CASE scope_identifier.kind
                        WHEN 'purl' THEN EXISTS (
                            SELECT 1 FROM sbom_node_purl_ref scope_ref
                            JOIN qualified_purl scope_purl ON scope_purl.id = scope_ref.qualified_purl_id
                            WHERE scope_ref.sbom_id = {sbom} AND scope_ref.node_id = scope_node.node_id
                              AND legacy_context_purl_matches(scope_identifier.value, scope_purl.purl)
                        )
                        WHEN 'digest' THEN EXISTS (
                            SELECT 1 FROM sbom_node_checksum checksum
                            WHERE checksum.sbom_id = {sbom} AND checksum.node_id = scope_node.node_id
                              AND lower(regexp_replace(checksum.type, '[^a-zA-Z0-9]', '', 'g')
                                        || ':' || checksum.value) = lower(scope_identifier.value)
                        )
                        ELSE EXISTS (
                            SELECT 1 FROM sbom_node_product_identifier product_identifier
                            WHERE product_identifier.sbom_id = {sbom}
                              AND product_identifier.node_id = scope_node.node_id
                              AND product_identifier.identifier_type = CASE scope_identifier.kind
                                  WHEN 'sku' THEN 'sku'::product_identifier_type
                                  WHEN 'model_number' THEN 'model_number'::product_identifier_type
                                  WHEN 'serial_number' THEN 'serial_number'::product_identifier_type
                              END
                              AND product_identifier.value LIKE {pattern}
                        )
                    END
                )
              END
        )"#
    )
}
