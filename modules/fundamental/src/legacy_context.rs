//! Package-local product applicability for the legacy query paths.
//!
//! This intentionally uses only PURL JSON and the existing CPE table, so it can
//! be backported without the correlation engine or additional database objects.
//! Main-only assertion identity handling is isolated in `assertion`.

pub(crate) mod assertion;

#[cfg(test)]
mod test;

/// Build a predicate from trusted SQL expressions (never interpolate input values).
/// `explicit` proves a describing context; `missing` is the legacy no-context
/// fallback. Recognized RHEL packages must not use that unrestricted fallback.
///
/// `bound` is an RPM package range bound, or `NULL::text` for product statuses:
/// product-version ranges must not be compared with installed package versions.
pub(crate) fn filter(
    context: &str,
    purl: &str,
    bound: &str,
    explicit: &str,
    missing: &str,
    proven_attributes: &str,
) -> String {
    format!(
        r#"(CASE
    WHEN {context} IS NULL THEN true
    WHEN ({purl}->>'ty' = 'rpm' AND {purl}->>'namespace' = 'redhat') IS NOT TRUE
    THEN (({explicit}) OR ({missing}))
    ELSE (
        SELECT CASE
            WHEN hints.distro IS NOT NULL OR streams.installed_major IS NOT NULL
            THEN COALESCE(CASE
                -- Invalid/contradictory hints cannot manufacture a scope or
                -- reactivate the no-describing-CPE fallback.
                WHEN (hints.distro IS NOT NULL AND majors.distro_major IS NULL)
                  OR (majors.distro_major IS NOT NULL
                      AND streams.installed_major IS NOT NULL
                      AND majors.distro_major <> streams.installed_major)
                THEN ({explicit}) AND (
                    ({unrestricted} AND scope.edition = '*' AND scope.target_hw = '*')
                    OR ({proven_attributes})
                )
                WHEN scope.vendor = 'redhat' AND scope.product = 'enterprise_linux'
                THEN scope.part IN ('a', 'o', '*')
                    AND (scope.version = '*' OR (
                        scope.version ~ '^[0-9]+([.][0-9]+)*$'
                        AND split_part(scope.version, '.', 1) =
                            COALESCE(majors.distro_major, streams.installed_major)
                    ))
                    -- BaseOS and AppStream label ordinary RHEL repositories,
                    -- not a separate product. Other editions still need proof.
                    AND (({unrestricted}
                    AND scope.edition IN ('*', 'baseos', 'appstream')
                    AND (scope.target_hw = '*' OR scope.target_hw = package.purl #>> '{{qualifiers,arch}}'))
                    OR ({proven_attributes}))
                    -- Like the release's stream_match: same-major minor
                    -- streams are compatible; different dist families are not.
                    AND (streams.installed IS NULL OR streams.stated IS NULL
                         OR streams.installed = streams.stated)
                -- An el-tagged build alone cannot identify a layered product.
                -- Its actual describing CPE can, without reviving the no-root fallback.
                ELSE ({proven_attributes})
            END, false)
            ELSE (({explicit}) OR ({missing}))
        END
        FROM (SELECT {purl} AS purl) package
        -- These are single-row projections. Keep PostgreSQL from inlining
        -- them and repeating the release/distro expressions in each branch.
        CROSS JOIN LATERAL (
            SELECT package.purl #>> '{{qualifiers,distro}}' AS distro,
                   NULLIF(split_part(package.purl->>'version', '-', -1), package.purl->>'version') AS release,
                   NULLIF(split_part({bound}, '-', -1), {bound}) AS bound_release
            OFFSET 0
        ) hints
        CROSS JOIN LATERAL (
            SELECT substring(hints.distro FROM '^rhel-([0-9]+)(?:[.][0-9]+)?$') AS distro_major
            OFFSET 0
        ) majors
        CROSS JOIN LATERAL (
            SELECT substring(hints.release FROM '(?:^|[.+_])el([0-9]+)(?:[._+]|$)') AS installed_major,
                   substring(hints.release FROM '(?:^|[.])([[:alpha:]]+[0-9]+)') AS installed,
                   substring(hints.bound_release FROM '(?:^|[.])([[:alpha:]]+[0-9]+)') AS stated
            OFFSET 0
        ) streams
        LEFT JOIN cpe scope ON scope.id = {context}
    )
END)"#,
        unrestricted = "scope.update = '*' AND scope.language = '*'
                         AND scope.sw_edition = '*' AND scope.target_sw = '*' AND scope.other = '*'",
    )
}

/// Existing describing-CPE rules, kept separate from the no-context fallback.
/// The SBOM expression can be a parameter or a correlated package reference.
pub(crate) fn describing(context: &str, sbom: &str) -> (String, String) {
    (
        format!(
            r#"{context} IN (
                SELECT cpe_id FROM sbom_describing_cpe WHERE sbom_id = {sbom}
                UNION
                SELECT c.id
                FROM sbom_describing_cpe d
                JOIN cpe original ON original.id = d.cpe_id
                JOIN cpe c ON c.vendor = original.vendor AND c.product = original.product
                    AND c.version = split_part(original.version, '.', 1)
                WHERE d.sbom_id = {sbom}
            )"#
        ),
        format!("NOT EXISTS (SELECT 1 FROM sbom_describing_cpe WHERE sbom_id = {sbom})"),
    )
}

/// Prove restricted attributes against the owning SBOM's actual root, not the
/// legacy generalized-ID union (which also includes other editions/architectures).
pub(crate) fn attribute_proof(sbom_condition: &str) -> String {
    let attributes = [
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ]
    .map(|field| format!("(scope.{field} = '*' OR scope.{field} = proof_root.{field})"))
    .join(" AND ");
    format!(
        r#"EXISTS (
        SELECT 1 FROM sbom_describing_cpe proof_d
        JOIN cpe proof_root ON proof_root.id = proof_d.cpe_id
        WHERE {sbom_condition}
          AND scope.vendor = proof_root.vendor AND scope.product = proof_root.product
          AND (scope.part = '*' OR scope.part = proof_root.part)
          AND (scope.version = '*' OR scope.version = proof_root.version
               OR scope.version = split_part(proof_root.version, '.', 1))
          AND {attributes}
    )"#
    )
}
