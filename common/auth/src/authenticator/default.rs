use std::collections::HashMap;

/// Default scope mappings (in a `const` form).
///
/// See [`default_scope_mappings`] for a `HashMap` form.
///
/// This should be aligned with the default Keycloak configuration we use for local deployments.
/// It can be overridden by configuration.
pub const DEFAULT_SCOPE_MAPPINGS: &[(&str, &[&str])] = &[
    (
        "create:document",
        &[
            "create.advisory",
            "create.importer",
            "create.metadata",
            "create.sbom",
            "create.sbomGroup",
            "create.weakness",
            "upload.dataset",
        ],
    ),
    (
        "read:document",
        &[
            "ai",
            "read.advisory",
            "read.importer",
            "read.metadata",
            "read.sbom",
            "read.sbomGroup",
            "read.weakness",
            "read.systemInformation",
        ],
    ),
    (
        "update:document",
        &[
            "update.advisory",
            "update.importer",
            "update.metadata",
            "update.sbom",
            "update.sbomGroup",
            "update.weakness",
        ],
    ),
    (
        "delete:document",
        &[
            "delete.advisory",
            "delete.importer",
            "delete.metadata",
            "delete.sbom",
            "delete.sbomGroup",
            "delete.vulnerability",
            "delete.weakness",
        ],
    ),
];

/// A convenience function to get the default scopes in an allocated form.
pub fn default_scope_mappings() -> HashMap<String, Vec<String>> {
    DEFAULT_SCOPE_MAPPINGS
        .iter()
        .map(|(k, v)| (k.to_string(), v.iter().map(ToString::to_string).collect()))
        .collect()
}
