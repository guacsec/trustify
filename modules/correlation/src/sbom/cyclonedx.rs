use crate::types::{ComponentId, SbomComponent, SbomInput, parse_purl};

/// Extract components and describing CPEs from a CycloneDX SBOM.
pub fn extract(name: &str, doc: &serde_json::Value) -> SbomInput {
    let mut components = Vec::new();
    let mut describing_cpes = Vec::new();

    // The metadata.component is the "described" product — its CPE is the describing CPE.
    if let Some(meta_comp) = doc.pointer("/metadata/component") {
        extract_component(meta_comp, &mut components);

        if let Some(cpe) = meta_comp.get("cpe").and_then(|v| v.as_str()) {
            describing_cpes.push(cpe.to_string());
        }
    }

    if let Some(comps) = doc.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            extract_component(comp, &mut components);
        }
    }

    // Components with a CPE that are referenced by a "describes" dependency
    // also contribute describing CPEs. The describes relationship in CycloneDX
    // is implicit via metadata.component → dependencies, but for synthetic
    // test SBOMs, CPEs on child components may also be describing.
    // We handle this by checking which bom-refs are dependsOn from the root.
    let root_ref = doc
        .pointer("/metadata/component/bom-ref")
        .and_then(|v| v.as_str());

    if let (Some(root), Some(deps)) = (root_ref, doc.get("dependencies").and_then(|v| v.as_array()))
    {
        let described_refs: Vec<&str> = deps
            .iter()
            .filter(|d| d.get("ref").and_then(|v| v.as_str()) == Some(root))
            .flat_map(|d| {
                d.get("dependsOn")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str())
            })
            .collect();

        if let Some(comps) = doc.get("components").and_then(|v| v.as_array()) {
            for comp in comps {
                let bom_ref = comp.get("bom-ref").and_then(|v| v.as_str());
                if let Some(br) = bom_ref
                    && described_refs.contains(&br)
                    && let Some(cpe) = comp.get("cpe").and_then(|v| v.as_str())
                    && !describing_cpes.contains(&cpe.to_string())
                {
                    describing_cpes.push(cpe.to_string());
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
