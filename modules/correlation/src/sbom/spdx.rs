use crate::types::{ComponentId, SbomComponent, SbomInput, parse_purl};

/// Extract components from an SPDX SBOM.
pub fn extract(name: &str, doc: &serde_json::Value) -> SbomInput {
    let mut components = Vec::new();

    if let Some(packages) = doc.get("packages").and_then(|v| v.as_array()) {
        for pkg in packages {
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
                    }
                    _ => {}
                }
            }
        }
    }

    SbomInput {
        name: name.to_string(),
        components,
    }
}
