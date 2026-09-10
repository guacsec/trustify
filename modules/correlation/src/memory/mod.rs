use std::collections::HashMap;

use crate::{
    engine::{Collector, CorrelationEngine},
    extract,
    sbom::extract_sbom,
    types::{
        AssertionRef, ComponentId, ComponentMatcher, ComponentQuery, MatchDimension, MatchEvidence,
        SbomInput, StatusAssertion, TraceEntry, Verdict,
    },
    version::version_matches,
};

/// An in-memory correlation engine that loads advisories from parsed JSON.
pub struct InMemoryEngine {
    assertions: Vec<StatusAssertion>,
}

impl InMemoryEngine {
    pub fn new() -> Self {
        Self {
            assertions: Vec::new(),
        }
    }

    /// Load a single advisory JSON document.
    pub fn load_advisory(&mut self, source_file: &str, json: &serde_json::Value) {
        let extracted = extract::extract_advisory(source_file, json);
        self.assertions.extend(extracted);
    }

    /// Load an SBOM and correlate all its components, returning the parsed SBOM.
    pub fn load_and_correlate_sbom(
        &self,
        name: &str,
        json: &serde_json::Value,
        collector: &mut dyn Collector,
    ) -> Option<SbomInput> {
        let sbom = extract_sbom(name, json)?;
        self.correlate_sbom(&sbom, collector);
        Some(sbom)
    }

    /// Return the number of loaded assertions.
    pub fn assertion_count(&self) -> usize {
        self.assertions.len()
    }
}

impl Default for InMemoryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine for InMemoryEngine {
    fn correlate_component(&self, component: &ComponentQuery, collector: &mut dyn Collector) {
        collector.on_trace(&TraceEntry {
            message: format!(
                "correlating component: {}",
                format_component_id(&component.id)
            ),
            detail: None,
        });

        let mut by_vuln: HashMap<&str, Vec<&StatusAssertion>> = HashMap::new();
        let mut identity_match_count = 0u32;

        for assertion in &self.assertions {
            if matches_component(&component.id, &assertion.matcher) {
                identity_match_count += 1;
                let version_in_range = check_version(&component.id, &assertion.matcher);

                collector.on_match(&MatchEvidence {
                    assertion_source: assertion.source.clone(),
                    vulnerability_id: assertion.vulnerability_id.clone(),
                    status: assertion.status,
                    dimension: match_dimension(&assertion.matcher),
                    version_in_range: Some(version_in_range),
                });

                let qualifier = if version_in_range {
                    "EFFECTIVE"
                } else {
                    "SKIPPED (version out of range)"
                };

                collector.on_trace(&TraceEntry {
                    message: format!(
                        "  {} {} {} from {} [{}]",
                        qualifier,
                        assertion.vulnerability_id,
                        assertion.status.as_str(),
                        assertion.source.identifier,
                        format_matcher(&assertion.matcher),
                    ),
                    detail: if !version_in_range {
                        Some(explain_skip(&component.id, &assertion.matcher))
                    } else {
                        None
                    },
                });

                if version_in_range {
                    by_vuln
                        .entry(&assertion.vulnerability_id)
                        .or_default()
                        .push(assertion);
                }
            }
        }

        if identity_match_count == 0 {
            collector.on_trace(&TraceEntry {
                message: "  no identity matches found in any assertion".into(),
                detail: None,
            });
        }

        for (vuln_id, matching) in &by_vuln {
            let verdict = resolve_verdict(vuln_id, matching, collector);
            collector.on_verdict(&verdict);
        }
    }

    fn correlate_sbom(&self, sbom: &SbomInput, collector: &mut dyn Collector) {
        collector.on_trace(&TraceEntry {
            message: format!(
                "correlating SBOM '{}' with {} components and {} assertions",
                sbom.name,
                sbom.components.len(),
                self.assertions.len()
            ),
            detail: None,
        });

        for component in &sbom.components {
            let query = ComponentQuery {
                id: component.id.clone(),
            };
            self.correlate_component(&query, collector);
        }
    }
}

/// Check whether an assertion's matcher identifies the same component.
fn matches_component(component: &ComponentId, matcher: &ComponentMatcher) -> bool {
    match (component, matcher) {
        (
            ComponentId::Purl {
                ty: comp_ty,
                namespace: comp_ns,
                name: comp_name,
                ..
            },
            ComponentMatcher::Purl {
                ty: match_ty,
                namespace: match_ns,
                name: match_name,
                qualifiers,
                ..
            },
        ) => {
            if comp_ty != match_ty {
                return false;
            }
            if comp_ns != match_ns {
                return false;
            }
            if comp_name != match_name {
                return false;
            }
            if !qualifiers_match(qualifiers, component) {
                return false;
            }
            true
        }
        (ComponentId::Cpe(comp_cpe), ComponentMatcher::CpeMatch { cpe: match_cpe, .. }) => {
            cpe_prefix_matches(comp_cpe, match_cpe)
        }
        (
            ComponentId::Purl {
                name: comp_name, ..
            },
            ComponentMatcher::CveProduct { product, .. },
        ) => comp_name.eq_ignore_ascii_case(product),
        _ => false,
    }
}

fn qualifiers_match(
    expected: &std::collections::BTreeMap<String, String>,
    component: &ComponentId,
) -> bool {
    let ComponentId::Purl {
        qualifiers: actual, ..
    } = component
    else {
        return false;
    };

    expected
        .iter()
        .filter(|(key, _)| key.as_str() != "epoch")
        .all(|(key, value)| actual.get(key).is_some_and(|actual| actual == value))
}

/// Check whether the component's version satisfies the assertion's version constraint.
fn check_version(component: &ComponentId, matcher: &ComponentMatcher) -> bool {
    let comp_version = match component {
        ComponentId::Purl {
            version: Some(v),
            ty,
            qualifiers,
            ..
        } => {
            // For RPM, prepend epoch if present and non-zero
            if ty == "rpm" {
                if let Some(epoch) = qualifiers.get("epoch") {
                    if epoch != "0" {
                        format!("{epoch}:{v}")
                    } else {
                        v.clone()
                    }
                } else {
                    v.clone()
                }
            } else {
                v.clone()
            }
        }
        ComponentId::Purl { version: None, .. } => return true,
        ComponentId::Cpe(cpe) => match cpe_version(cpe) {
            Some(v) => v,
            None => return true,
        },
        _ => return true,
    };

    let constraint = match matcher {
        ComponentMatcher::Purl {
            version: Some(vc), ..
        } => vc,
        ComponentMatcher::Purl { version: None, .. } => return false,
        ComponentMatcher::CpeMatch {
            version: Some(vc), ..
        } => vc,
        ComponentMatcher::CpeMatch { version: None, .. } => return true,
        ComponentMatcher::CveProduct { version: vc, .. } => vc,
    };

    version_matches(&comp_version, &constraint.range, constraint.scheme)
}

/// Normalize a CPE string to CPE 2.3 format for comparison.
/// Converts `cpe:/part:vendor:product:version...` (2.2) to
/// `cpe:2.3:part:vendor:product:version:*:*:*:*:*:*:*` (2.3).
fn normalize_cpe(cpe: &str) -> Vec<String> {
    if cpe.starts_with("cpe:2.3:") {
        cpe.split(':').map(|s| s.to_lowercase()).collect()
    } else if let Some(rest) = cpe.strip_prefix("cpe:/") {
        let mut parts = vec!["cpe".to_string(), "2.3".to_string()];
        for segment in rest.split(':') {
            parts.push(segment.to_lowercase());
        }
        while parts.len() < 13 {
            parts.push("*".to_string());
        }
        parts
    } else {
        cpe.split(':').map(|s| s.to_lowercase()).collect()
    }
}

/// Extract the version from a CPE string (index 5 in normalized CPE 2.3).
fn cpe_version(cpe: &str) -> Option<String> {
    let parts = normalize_cpe(cpe);
    parts.get(5).filter(|v| v.as_str() != "*").cloned()
}

/// CPE prefix match — does `candidate` match `pattern`?
/// Normalizes both to CPE 2.3, then compares segments. `*` matches any segment.
fn cpe_prefix_matches(candidate: &str, pattern: &str) -> bool {
    let cand_parts = normalize_cpe(candidate);
    let pat_parts = normalize_cpe(pattern);

    for (i, pat) in pat_parts.iter().enumerate() {
        if pat == "*" {
            continue;
        }
        match cand_parts.get(i) {
            Some(cand) => {
                if cand == "*" {
                    continue;
                }
                if cand != pat {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

fn format_component_id(id: &ComponentId) -> String {
    match id {
        ComponentId::Purl {
            ty,
            namespace,
            name,
            version,
            ..
        } => {
            let ns = namespace
                .as_deref()
                .map(|n| format!("{n}/"))
                .unwrap_or_default();
            let ver = version
                .as_deref()
                .map(|v| format!("@{v}"))
                .unwrap_or_default();
            format!("pkg:{ty}/{ns}{name}{ver}")
        }
        ComponentId::Cpe(cpe) => cpe.clone(),
        ComponentId::Hash { algorithm, value } => format!("{algorithm}:{value}"),
    }
}

fn format_matcher(matcher: &ComponentMatcher) -> String {
    match matcher {
        ComponentMatcher::Purl {
            ty,
            namespace,
            name,
            qualifiers,
            version,
        } => {
            let ns = namespace
                .as_deref()
                .map(|n| format!("{n}/"))
                .unwrap_or_default();
            let ver = version
                .as_ref()
                .map(|v| format!(" version={}", v.range))
                .unwrap_or_default();
            let qualifiers = if qualifiers.is_empty() {
                String::new()
            } else {
                format!(" qualifiers={qualifiers:?}")
            };
            format!("purl:{ty}/{ns}{name}{qualifiers}{ver}")
        }
        ComponentMatcher::CpeMatch { cpe, version } => {
            let ver = version
                .as_ref()
                .map(|v| format!(" version={}", v.range))
                .unwrap_or_default();
            format!("cpe:{cpe}{ver}")
        }
        ComponentMatcher::CveProduct { product, version } => {
            format!("product:{product} version={}", version.range)
        }
    }
}

fn explain_skip(component: &ComponentId, matcher: &ComponentMatcher) -> String {
    let comp_ver = match component {
        ComponentId::Purl {
            version: Some(v), ..
        } => v.as_str(),
        _ => "(none)",
    };
    let constraint = match matcher {
        ComponentMatcher::Purl {
            version: Some(vc), ..
        } => format!("{}", vc.range),
        ComponentMatcher::CpeMatch {
            version: Some(vc), ..
        } => format!("{}", vc.range),
        ComponentMatcher::CveProduct { version: vc, .. } => format!("{}", vc.range),
        _ => "(none)".into(),
    };
    format!("component version '{comp_ver}' is outside {constraint}")
}

fn match_dimension(matcher: &ComponentMatcher) -> MatchDimension {
    match matcher {
        ComponentMatcher::Purl { .. } | ComponentMatcher::CveProduct { .. } => MatchDimension::Purl,
        ComponentMatcher::CpeMatch { .. } => MatchDimension::Cpe,
    }
}

#[cfg(test)]
mod tests {
    use super::qualifiers_match;
    use crate::types::ComponentId;
    use std::collections::BTreeMap;

    fn component(qualifiers: &[(&str, &str)]) -> ComponentId {
        ComponentId::Purl {
            ty: "rpm".into(),
            namespace: Some("redhat".into()),
            name: "kernel-core".into(),
            version: Some("6.12.0-211.30.1.el10_2".into()),
            qualifiers: qualifiers
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
        }
    }

    #[test]
    fn qualifier_match_requires_matching_values() {
        let expected = BTreeMap::from([(String::from("distro"), String::from("rhel-8"))]);

        assert!(!qualifiers_match(
            &expected,
            &component(&[("distro", "rhel-10")]),
        ));
        assert!(qualifiers_match(
            &expected,
            &component(&[("distro", "rhel-8"), ("arch", "x86_64")]),
        ));
    }

    #[test]
    fn empty_qualifier_matcher_matches_any_qualifiers() {
        assert!(qualifiers_match(
            &BTreeMap::new(),
            &component(&[("arch", "x86_64")])
        ));
    }

    #[test]
    fn epoch_qualifier_is_version_metadata_not_identity() {
        let expected = BTreeMap::from([(String::from("epoch"), String::from("1"))]);

        assert!(qualifiers_match(&expected, &component(&[])));
    }
}

/// Resolve conflicting assertions for the same vulnerability.
///
/// For PURL-matched assertions (with version constraints): fixed/not_affected
/// overrides affected at a specific version.
///
/// For CPE-only assertions (product-level): affected takes precedence because
/// any affected component under the product CPE makes the product affected.
fn resolve_verdict(
    vuln_id: &str,
    assertions: &[&StatusAssertion],
    collector: &mut dyn Collector,
) -> Verdict {
    use crate::types::Status;

    let mut has_affected = false;
    let mut has_resolution = false;
    let mut all_cpe_only = true;
    let mut contributing = Vec::new();

    for assertion in assertions {
        contributing.push(AssertionRef {
            source: assertion.source.clone(),
            status: assertion.status,
            matched_by: match_dimension(&assertion.matcher),
        });

        match assertion.status {
            Status::Affected => has_affected = true,
            Status::Fixed | Status::NotAffected => has_resolution = true,
            _ => {}
        }

        if !matches!(assertion.matcher, ComponentMatcher::CpeMatch { .. }) {
            all_cpe_only = false;
        }
    }

    let (final_status, reason) = if all_cpe_only && has_affected {
        (
            Status::Affected,
            "CPE-only match: affected wins at product level",
        )
    } else if has_resolution {
        let status = assertions
            .iter()
            .find(|a| a.status.resolves_affected())
            .map(|a| a.status)
            .unwrap_or(Status::NotAffected);
        (
            status,
            "PURL-level match: resolution (fixed/not_affected) overrides affected",
        )
    } else if has_affected {
        (Status::Affected, "only affected assertions matched")
    } else {
        let status = assertions
            .first()
            .map(|a| a.status)
            .unwrap_or(Status::Affected);
        (
            status,
            "no affected or resolution assertions; using first match",
        )
    };

    collector.on_trace(&TraceEntry {
        message: format!(
            "  VERDICT {vuln_id} = {} ({} contributing assertions)",
            final_status.as_str(),
            assertions.len(),
        ),
        detail: Some(reason.to_string()),
    });

    Verdict {
        vulnerability_id: vuln_id.to_string(),
        status: final_status,
        contributing_assertions: contributing,
    }
}
