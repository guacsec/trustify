//! Raw-document extraction boundary for advisory and SBOM evidence.

pub mod advisory;
pub mod sbom;

use crate::evidence::{AdvisoryEvidence, SbomEvidence};

/// Convert a raw advisory document into normalized advisory evidence.
///
/// Returns `None` when the document is not a recognized advisory format.
pub fn extract_advisory(
    source_file: &str,
    document: &serde_json::Value,
) -> Option<AdvisoryEvidence> {
    advisory::extract(source_file, document).map(|assertions| AdvisoryEvidence { assertions })
}

/// Convert a raw SBOM document into normalized SBOM evidence.
pub fn extract_sbom(name: &str, document: &serde_json::Value) -> Option<SbomEvidence> {
    sbom::extract(name, document)
}
