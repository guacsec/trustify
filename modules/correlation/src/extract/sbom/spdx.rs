//! SPDX package, describing-relationship, and dependency extraction.

use crate::evidence::SbomEvidence;
use crate::types::{
    ComponentId, ContextKind, ContextRef, GroupRef, GroupingRelation, SbomComponent, parse_purl,
};
use std::collections::BTreeMap;

/// Extract components from an SPDX SBOM.
pub fn extract(name: &str, doc: &serde_json::Value) -> SbomEvidence {
    let mut components = Vec::new();
    let mut package_ids = BTreeMap::new();

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
                            package_ids.insert(pkg_id(pkg), id.clone());
                            components.push(SbomComponent {
                                id,
                                context: Vec::new(),
                                grouping: Vec::new(),
                            });
                        }
                    }
                    (Some("cpe22Type" | "cpe23Type"), Some(cpe)) => {
                        let id = ComponentId::Cpe(cpe.to_string());
                        package_ids.insert(pkg_id(pkg), id.clone());
                        components.push(SbomComponent {
                            id,
                            context: Vec::new(),
                            grouping: Vec::new(),
                        });
                    }
                    _ => {}
                }
            }

            if let Some(checksums) = pkg.get("checksums").and_then(|value| value.as_array()) {
                for checksum in checksums {
                    let Some(algorithm) =
                        checksum.get("algorithm").and_then(|value| value.as_str())
                    else {
                        continue;
                    };
                    let Some(value) = checksum
                        .get("checksumValue")
                        .and_then(|value| value.as_str())
                    else {
                        continue;
                    };
                    components.push(SbomComponent {
                        id: ComponentId::Hash {
                            algorithm: algorithm.to_string(),
                            value: value.to_string(),
                        },
                        context: Vec::new(),
                        grouping: Vec::new(),
                    });
                }
            }
        }
    }

    let mut context = Vec::new();
    let mut grouping = Vec::new();
    if let Some(relationships) = doc.get("relationships").and_then(|v| v.as_array()) {
        for relationship in relationships {
            let subject = relationship
                .get("spdxElementId")
                .and_then(|v| v.as_str())
                .and_then(|id| package_ids.get(id))
                .cloned();
            let target = relationship
                .get("relatedSpdxElement")
                .and_then(|v| v.as_str())
                .and_then(|id| package_ids.get(id))
                .cloned();
            let Some(target) = target else { continue };
            let relation = match relationship
                .get("relationshipType")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
            {
                "DESCRIBES" => {
                    context.push(ContextRef {
                        id: target.clone(),
                        kind: ContextKind::Product,
                    });
                    GroupingRelation::Describes
                }
                "DEPENDS_ON" => GroupingRelation::DependsOn,
                "CONTAINS" => GroupingRelation::Contains,
                _ => GroupingRelation::Other,
            };
            if let Some(subject) = subject {
                grouping.push(GroupRef {
                    subject,
                    target,
                    relationship: relation,
                });
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

fn pkg_id(pkg: &serde_json::Value) -> String {
    pkg.get("SPDXID")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod test {
    use super::extract;
    use crate::types::ComponentId;

    #[test]
    fn extracts_package_checksums() {
        let document = serde_json::json!({
            "packages": [{
                "SPDXID": "SPDXRef-Package",
                "name": "firmware",
                "checksums": [{
                    "algorithm": "SHA256",
                    "checksumValue": "abc123"
                }]
            }],
            "relationships": []
        });

        let evidence = extract("test.spdx.json", &document);
        assert!(evidence.components.iter().any(|component| {
            component.id
                == (ComponentId::Hash {
                    algorithm: "SHA256".into(),
                    value: "abc123".into(),
                })
        }));
    }
}
