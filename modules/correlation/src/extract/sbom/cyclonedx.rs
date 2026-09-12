//! CycloneDX component, metadata-context, and dependency extraction.

use crate::evidence::SbomEvidence;
use crate::types::{
    ComponentId, ContextKind, ContextRef, GroupRef, GroupingRelation, SbomComponent, parse_purl,
};
use std::collections::BTreeMap;

/// Extract components from a CycloneDX SBOM.
pub fn extract(name: &str, doc: &serde_json::Value) -> SbomEvidence {
    let mut components = Vec::new();
    let mut context = Vec::new();

    if let Some(meta_comp) = doc.pointer("/metadata/component") {
        extract_component(meta_comp, &mut components);
        extract_context(meta_comp, &mut context);
    }

    if let Some(comps) = doc.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            extract_component(comp, &mut components);
        }
    }

    let mut ids = BTreeMap::new();
    if let Some(comps) = doc.get("components").and_then(|v| v.as_array()) {
        for comp in comps {
            let Some(reference) = comp.get("bom-ref").and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some(id) = component_id(comp) {
                ids.insert(reference.to_string(), id);
            }
        }
    }
    let mut grouping = Vec::new();
    if let Some(dependencies) = doc.get("dependencies").and_then(|v| v.as_array()) {
        for dependency in dependencies {
            let Some(subject) = dependency
                .get("ref")
                .and_then(|v| v.as_str())
                .and_then(|reference| ids.get(reference))
                .cloned()
            else {
                continue;
            };
            if let Some(targets) = dependency.get("dependsOn").and_then(|v| v.as_array()) {
                for target in targets.iter().filter_map(|target| target.as_str()) {
                    if let Some(target) = ids.get(target).cloned() {
                        grouping.push(GroupRef {
                            subject: subject.clone(),
                            target,
                            relationship: GroupingRelation::DependsOn,
                        });
                    }
                }
            }
        }
    }

    SbomEvidence {
        name: name.to_string(),
        components,
        context,
        grouping,
    }
}

fn component_id(comp: &serde_json::Value) -> Option<ComponentId> {
    if let Some(purl) = comp.get("purl").and_then(|v| v.as_str()) {
        parse_purl(purl)
    } else {
        comp.get("cpe")
            .and_then(|v| v.as_str())
            .map(|cpe| ComponentId::Cpe(cpe.to_string()))
    }
}

fn extract_component(comp: &serde_json::Value, out: &mut Vec<SbomComponent>) {
    if let Some(purl_str) = comp.get("purl").and_then(|v| v.as_str())
        && let Some(id) = parse_purl(purl_str)
    {
        out.push(SbomComponent {
            id,
            context: Vec::new(),
            grouping: Vec::new(),
        });
    }

    if let Some(cpe) = comp.get("cpe").and_then(|v| v.as_str()) {
        out.push(SbomComponent {
            id: ComponentId::Cpe(cpe.to_string()),
            context: Vec::new(),
            grouping: Vec::new(),
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
                        out.push(SbomComponent {
                            id,
                            context: Vec::new(),
                            grouping: Vec::new(),
                        });
                    }
                }
                (Some("cpe"), Some(cpe)) => {
                    out.push(SbomComponent {
                        id: ComponentId::Cpe(cpe.to_string()),
                        context: Vec::new(),
                        grouping: Vec::new(),
                    });
                }
                _ => {}
            }
        }
    }
}

fn extract_context(comp: &serde_json::Value, out: &mut Vec<ContextRef>) {
    if let Some(purl) = comp.get("purl").and_then(|v| v.as_str())
        && let Some(id) = parse_purl(purl)
    {
        out.push(ContextRef {
            id,
            kind: ContextKind::Product,
        });
    }
    if let Some(cpe) = comp.get("cpe").and_then(|v| v.as_str()) {
        out.push(ContextRef {
            id: ComponentId::Cpe(cpe.to_string()),
            kind: ContextKind::Product,
        });
    }
}
