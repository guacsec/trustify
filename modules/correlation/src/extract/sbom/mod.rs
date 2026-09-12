//! SBOM format dispatch into normalized component evidence.

pub mod cyclonedx;
pub mod spdx;

use crate::evidence::SbomEvidence;

/// Detect SBOM format and extract normalized SBOM facts.
pub fn extract(name: &str, json: &serde_json::Value) -> Option<SbomEvidence> {
    if json.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX") {
        Some(cyclonedx::extract(name, json))
    } else if json.get("spdxVersion").and_then(|v| v.as_str()).is_some() {
        Some(spdx::extract(name, json))
    } else {
        None
    }
}
