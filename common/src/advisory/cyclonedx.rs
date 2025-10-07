use serde_cyclonedx::cyclonedx::v_1_6::CycloneDx;
use std::collections::HashMap;

/// extract CycloneDX SBOM general purpose properties
pub fn extract_properties(sbom: &CycloneDx) -> HashMap<String, Option<String>> {
    sbom.properties
        .iter()
        .flatten()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect()
}

/// extract CycloneDX SBOM general purpose properties, convert into [`serde_json::Value`]
pub fn extract_properties_json(sbom: &CycloneDx) -> serde_json::Value {
    serde_json::Value::Object(
        extract_properties(sbom)
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    v.map(serde_json::Value::String)
                        .unwrap_or(serde_json::Value::Null),
                )
            })
            .collect(),
    )
}
