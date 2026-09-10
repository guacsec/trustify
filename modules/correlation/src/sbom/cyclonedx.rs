use crate::types::{ComponentId, SbomComponent, SbomInput, parse_purl};

/// Extract components from a CycloneDX SBOM.
pub fn extract(name: &str, doc: &serde_json::Value) -> SbomInput {
    let mut components = Vec::new();

    if let Some(meta_comp) = doc.pointer("/metadata/component") {
        extract_component(meta_comp, &mut components);
    }

    if let Some(comps) = doc.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            extract_component(comp, &mut components);
        }
    }

    SbomInput {
        name: name.to_string(),
        components,
    }
}

fn extract_component(comp: &serde_json::Value, out: &mut Vec<SbomComponent>) {
    if let Some(purl_str) = comp.get("purl").and_then(|v| v.as_str())
        && let Some(id) = parse_purl(purl_str)
    {
        out.push(SbomComponent { id });
        return;
    }

    if let Some(cpe) = comp.get("cpe").and_then(|v| v.as_str()) {
        out.push(SbomComponent {
            id: ComponentId::Cpe(cpe.to_string()),
        });
    }

    // Evidence identities can provide additional PURLs/CPEs
    if let Some(identities) = comp
        .pointer("/evidence/identity")
        .and_then(|v| v.as_array())
    {
        for identity in identities {
            let field = identity.get("field").and_then(|v| v.as_str());
            let value = identity
                .get("concluded_value")
                .and_then(|v| v.as_str())
                .or_else(|| identity.get("concludedValue").and_then(|v| v.as_str()));

            match (field, value) {
                (Some("purl"), Some(purl_str)) => {
                    if let Some(id) = parse_purl(purl_str) {
                        out.push(SbomComponent { id });
                    }
                }
                (Some("cpe"), Some(cpe)) => {
                    out.push(SbomComponent {
                        id: ComponentId::Cpe(cpe.to_string()),
                    });
                }
                _ => {}
            }
        }
    }
}
