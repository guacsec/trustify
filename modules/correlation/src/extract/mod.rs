pub mod csaf;
pub mod cve;
pub mod osv;

use crate::types::StatusAssertion;

/// Detect advisory format and extract status assertions.
pub fn extract_advisory(source_file: &str, json: &serde_json::Value) -> Vec<StatusAssertion> {
    if json.pointer("/document/csaf_version").is_some() {
        csaf::extract(source_file, json)
    } else if json.get("dataType").and_then(|v| v.as_str()) == Some("CVE_RECORD") {
        cve::extract(source_file, json)
    } else if json.get("schema_version").is_some() && json.get("affected").is_some() {
        osv::extract(source_file, json)
    } else {
        Vec::new()
    }
}
