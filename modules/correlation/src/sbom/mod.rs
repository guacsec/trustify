pub mod cyclonedx;
pub mod spdx;

use crate::types::SbomInput;

/// Detect format and extract components from an SBOM JSON document.
pub fn extract_sbom(name: &str, json: &serde_json::Value) -> Option<SbomInput> {
    if json.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        Some(cyclonedx::extract(name, json))
    } else if json.get("spdxVersion").and_then(|v| v.as_str()).is_some() {
        Some(spdx::extract(name, json))
    } else {
        None
    }
}
