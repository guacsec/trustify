//! Advisory format dispatch into normalized status assertions.

pub mod csaf;
pub mod cve;
pub mod osv;

use crate::types::StatusAssertion;

/// Detect advisory format and extract status assertions.
///
/// Returns `None` when the document does not match any known advisory format,
/// mirroring [`crate::extract::sbom::extract`]. A recognized document with no
/// applicable assertions yields `Some(vec![])`, which is distinct from an
/// unrecognized format.
pub fn extract(source_file: &str, json: &serde_json::Value) -> Option<Vec<StatusAssertion>> {
    if json.pointer("/document/csaf_version").is_some() {
        Some(csaf::extract(source_file, json))
    } else if json.get("dataType").and_then(|v| v.as_str()) == Some("CVE_RECORD") {
        Some(cve::extract(source_file, json))
    } else if json.get("schema_version").is_some() && json.get("affected").is_some() {
        Some(osv::extract(source_file, json))
    } else {
        None
    }
}
