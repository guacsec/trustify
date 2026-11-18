//! Main-only assertion identity support. Keep this separate from the release's
//! CPE/RPM applicability rules; it needs neither extraction nor verdict snapshots.

/// A legacy CPE is checked by the caller's CPE predicate. Without that projection,
/// an assertion context needs positive evidence, rather than becoming global.
/// Match its CPEs using the same RPM/root rules (without the missing-root fallback),
/// or its exact product identifiers on this package or the owning SBOM root.
pub(crate) fn filter(
    context: &str,
    assertion: &str,
    purl: &str,
    bound: &str,
    sbom: &str,
    qualified_purl: &str,
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
    let nodes = format!(
        r#"SELECT owning.node_id FROM sbom owning WHERE owning.sbom_id = {sbom}
           UNION
           SELECT package_ref.node_id FROM sbom_node_purl_ref package_ref
           WHERE package_ref.sbom_id = {sbom}
             AND package_ref.qualified_purl_id = {qualified_purl}"#
    );
    // CSAF globs use * and ?, not SQL's % and _. Escape SQL metacharacters first.
    let pattern = r#"replace(replace(replace(replace(replace(scope_identifier.value,
        E'\\', E'\\\\'), '%', E'\\%'), '_', E'\\_'), '*', '%'), '?', '_')"#;
    format!(
        r#"({context} IS NOT NULL OR {assertion} IS NULL OR EXISTS (
            SELECT 1 FROM assertion_context_identifier scope_identifier
            WHERE scope_identifier.context_id = {assertion}
              AND (
                (scope_identifier.kind = 'cpe' AND scope_identifier.cpe_id IS NOT NULL
                 AND {cpe})
                OR EXISTS (
                    SELECT 1 FROM sbom_node_product_identifier product_identifier
                    WHERE product_identifier.sbom_id = {sbom}
                      AND product_identifier.node_id IN ({nodes})
                      AND product_identifier.identifier_type::text = scope_identifier.kind::text
                      AND product_identifier.value LIKE {pattern}
                )
                OR (scope_identifier.kind = 'digest' AND EXISTS (
                    SELECT 1 FROM sbom_node_checksum checksum
                    WHERE checksum.sbom_id = {sbom}
                      AND checksum.node_id IN ({nodes})
                      AND lower(regexp_replace(checksum.type, '[^a-zA-Z0-9]', '', 'g')
                                || ':' || checksum.value) = lower(scope_identifier.value)
                ))
              )
        ))"#
    )
}
