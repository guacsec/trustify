use crate::types::{
    AdvisoryRef, ComponentMatcher, Status, StatusAssertion, VersionConstraint, parse_purl,
};
use crate::version::{VersionRange, VersionScheme, vers::parse_vers};
use std::collections::HashMap;

/// Extract status assertions from a CSAF/VEX document.
pub fn extract(source_file: &str, doc: &serde_json::Value) -> Vec<StatusAssertion> {
    let tracking_id = doc
        .pointer("/document/tracking/id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let advisory_ref = AdvisoryRef {
        identifier: tracking_id,
        source_file: Some(source_file.to_string()),
    };

    let mut branch_index: HashMap<String, BranchInfo> = HashMap::new();
    let mut relationship_index: HashMap<String, RelationshipInfo> = HashMap::new();

    if let Some(pt) = doc.get("product_tree") {
        if let Some(branches) = pt.get("branches").and_then(|v| v.as_array()) {
            walk_branches(branches, &mut Vec::new(), &mut branch_index);
        }
        if let Some(rels) = pt.get("relationships").and_then(|v| v.as_array()) {
            index_relationships(rels, &mut branch_index, &mut relationship_index);
        }
    }

    let mut assertions = Vec::new();

    if let Some(vulns) = doc.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            let vuln_id = match vuln.get("cve").and_then(|v| v.as_str()) {
                Some(id) if !id.is_empty() => id,
                _ => continue,
            };

            if let Some(product_status) = vuln.get("product_status") {
                extract_product_status(
                    &advisory_ref,
                    vuln_id,
                    product_status,
                    &branch_index,
                    &relationship_index,
                    &mut assertions,
                );
            }
        }
    }

    assertions
}

#[derive(Debug, Clone, Default)]
struct BranchInfo {
    cpe: Option<String>,
    purl: Option<String>,
    #[allow(dead_code)]
    product_name: Option<String>,
    #[allow(dead_code)]
    vendor: Option<String>,
    version_range: Option<VersionConstraint>,
}

#[derive(Debug, Clone)]
struct RelationshipInfo {
    product_reference: String,
}

fn walk_branches(
    branches: &[serde_json::Value],
    parents: &mut Vec<BranchInfo>,
    index: &mut HashMap<String, BranchInfo>,
) {
    for branch in branches {
        let category = branch.get("category").and_then(|v| v.as_str());
        let name = branch.get("name").and_then(|v| v.as_str());

        let mut info = BranchInfo::default();

        for p in parents.iter() {
            if p.vendor.is_some() {
                info.vendor.clone_from(&p.vendor);
            }
            if p.cpe.is_some() {
                info.cpe.clone_from(&p.cpe);
            }
            if p.version_range.is_some() {
                info.version_range.clone_from(&p.version_range);
            }
        }

        match category {
            Some("vendor") => info.vendor = name.map(|s| s.to_string()),
            Some("product_name" | "product_family") => {
                info.product_name = name.map(|s| s.to_string());
            }
            Some("product_version_range") => {
                if let Some(vers_str) = name {
                    info.version_range = parse_vers(vers_str);
                }
            }
            _ => {}
        }

        if let Some(prod) = branch.get("product") {
            if let Some(pih) = prod.get("product_identification_helper") {
                if let Some(cpe) = pih.get("cpe").and_then(|v| v.as_str()) {
                    info.cpe = Some(cpe.to_string());
                }
                if let Some(purl) = pih.get("purl").and_then(|v| v.as_str()) {
                    info.purl = Some(purl.to_string());
                }
            }

            if let Some(pid) = prod.get("product_id").and_then(|v| v.as_str()) {
                index.insert(pid.to_string(), info.clone());
            }
        }

        parents.push(info);
        if let Some(children) = branch.get("branches").and_then(|v| v.as_array()) {
            walk_branches(children, parents, index);
        }
        parents.pop();
    }
}

fn index_relationships(
    rels: &[serde_json::Value],
    branch_index: &mut HashMap<String, BranchInfo>,
    rel_index: &mut HashMap<String, RelationshipInfo>,
) {
    for rel in rels {
        if let Some(full_product) = rel.get("full_product_name") {
            let product_id = match full_product.get("product_id").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let product_ref = rel
                .get("product_reference")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(pih) = full_product.get("product_identification_helper") {
                let info = BranchInfo {
                    cpe: pih.get("cpe").and_then(|v| v.as_str()).map(String::from),
                    purl: pih.get("purl").and_then(|v| v.as_str()).map(String::from),
                    product_name: full_product
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    vendor: None,
                    version_range: None,
                };
                branch_index.insert(product_id.clone(), info);
            }

            rel_index.insert(
                product_id,
                RelationshipInfo {
                    product_reference: product_ref,
                },
            );
        }
    }
}

fn extract_product_status(
    advisory_ref: &AdvisoryRef,
    vuln_id: &str,
    product_status: &serde_json::Value,
    branch_index: &HashMap<String, BranchInfo>,
    relationship_index: &HashMap<String, RelationshipInfo>,
    assertions: &mut Vec<StatusAssertion>,
) {
    let status_mappings = [
        ("fixed", Status::Fixed),
        ("known_affected", Status::Affected),
        ("known_not_affected", Status::NotAffected),
        ("under_investigation", Status::UnderInvestigation),
        ("recommended", Status::Recommended),
        ("first_fixed", Status::Fixed),
        ("first_affected", Status::Affected),
        ("last_affected", Status::Affected),
    ];

    for (field, status) in &status_mappings {
        if let Some(product_ids) = product_status.get(*field).and_then(|v| v.as_array()) {
            for pid_val in product_ids {
                let pid = match pid_val.as_str() {
                    Some(s) => s,
                    None => continue,
                };

                if let Some(matcher) = resolve_product_id(pid, branch_index, relationship_index) {
                    assertions.push(StatusAssertion {
                        source: advisory_ref.clone(),
                        vulnerability_id: vuln_id.to_string(),
                        status: *status,
                        matcher,
                    });
                }
            }
        }
    }
}

fn resolve_product_id(
    product_id: &str,
    branch_index: &HashMap<String, BranchInfo>,
    relationship_index: &HashMap<String, RelationshipInfo>,
) -> Option<ComponentMatcher> {
    if let Some(rel) = relationship_index.get(product_id) {
        let component_info = branch_index.get(&rel.product_reference);

        if let Some(info) = component_info
            && let Some(ref purl_str) = info.purl
        {
            return make_purl_matcher(purl_str, info.version_range.as_ref());
        }

        if let Some(info) = branch_index.get(product_id) {
            if let Some(ref purl_str) = info.purl {
                return make_purl_matcher(purl_str, info.version_range.as_ref());
            }
            if let Some(ref cpe) = info.cpe {
                return Some(ComponentMatcher::CpeMatch {
                    cpe: cpe.clone(),
                    version: None,
                });
            }
        }

        return None;
    }

    if let Some(info) = branch_index.get(product_id) {
        if let Some(ref purl_str) = info.purl {
            return make_purl_matcher(purl_str, info.version_range.as_ref());
        }
        if let Some(ref cpe) = info.cpe {
            return Some(ComponentMatcher::CpeMatch {
                cpe: cpe.clone(),
                version: None,
            });
        }
    }

    None
}

/// Build a PURL-based component matcher.
///
/// When `version_override` is provided (from a `product_version_range` branch), it
/// replaces the PURL's own version — this is how CSAF VERS ranges are applied.
fn make_purl_matcher(
    purl_str: &str,
    version_override: Option<&VersionConstraint>,
) -> Option<ComponentMatcher> {
    let parsed = parse_purl(purl_str)?;
    match parsed {
        crate::types::ComponentId::Purl {
            ty,
            namespace,
            name,
            version,
            qualifiers,
        } => {
            let version_constraint = if let Some(vc) = version_override {
                Some(vc.clone())
            } else {
                let effective_version = if ty == "rpm" {
                    if let (Some(v), Some(epoch)) = (&version, qualifiers.get("epoch")) {
                        if epoch != "0" {
                            Some(format!("{epoch}:{v}"))
                        } else {
                            version.clone()
                        }
                    } else {
                        version.clone()
                    }
                } else {
                    version.clone()
                };

                effective_version.map(|v| {
                    let scheme = VersionScheme::from(ty.as_str());
                    VersionConstraint {
                        scheme,
                        range: VersionRange::Exact(v),
                    }
                })
            };
            Some(ComponentMatcher::Purl {
                ty,
                namespace,
                name,
                qualifiers,
                version: version_constraint,
            })
        }
        _ => None,
    }
}
