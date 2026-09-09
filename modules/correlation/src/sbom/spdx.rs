use crate::types::{ComponentId, SbomComponent, SbomInput, parse_purl};
use std::collections::HashSet;

/// Extract components and describing CPEs from an SPDX SBOM.
pub fn extract(name: &str, doc: &serde_json::Value) -> SbomInput {
    let mut components = Vec::new();
    let mut describing_cpes = Vec::new();

    let described_ids = collect_described_ids(doc);

    if let Some(packages) = doc.get("packages").and_then(|v| v.as_array()) {
        for pkg in packages {
            let spdx_id = pkg.get("SPDXID").and_then(|v| v.as_str()).unwrap_or("");
            let is_describing = described_ids.contains(spdx_id);

            let ext_refs = pkg
                .get("externalRefs")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten();

            for ext_ref in ext_refs {
                let ref_type = ext_ref.get("referenceType").and_then(|v| v.as_str());
                let locator = ext_ref.get("referenceLocator").and_then(|v| v.as_str());

                match (ref_type, locator) {
                    (Some("purl"), Some(purl_str)) => {
                        if let Some(id) = parse_purl(purl_str) {
                            components.push(SbomComponent { id });
                        }
                    }
                    (Some("cpe22Type" | "cpe23Type"), Some(cpe)) => {
                        components.push(SbomComponent {
                            id: ComponentId::Cpe(cpe.to_string()),
                        });
                        if is_describing && !describing_cpes.contains(&cpe.to_string()) {
                            describing_cpes.push(cpe.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    SbomInput {
        name: name.to_string(),
        components,
        describing_cpes,
    }
}

fn collect_described_ids(doc: &serde_json::Value) -> HashSet<String> {
    let mut ids = HashSet::new();

    // From relationships with type DESCRIBES or DESCRIBED_BY
    if let Some(rels) = doc.get("relationships").and_then(|v| v.as_array()) {
        for rel in rels {
            let rel_type = rel.get("relationshipType").and_then(|v| v.as_str());
            match rel_type {
                Some("DESCRIBES") => {
                    if let Some(target) = rel.get("relatedSpdxElement").and_then(|v| v.as_str()) {
                        ids.insert(target.to_string());
                    }
                }
                Some("DESCRIBED_BY") => {
                    if let Some(source) = rel.get("spdxElementId").and_then(|v| v.as_str()) {
                        ids.insert(source.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    // Legacy: documentDescribes field
    if let Some(describes) = doc.get("documentDescribes").and_then(|v| v.as_array()) {
        for id in describes.iter().filter_map(|v| v.as_str()) {
            ids.insert(id.to_string());
        }
    }

    ids
}
