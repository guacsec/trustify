//! Identity and applicability matching for normalized component evidence.

use crate::{
    evidence::SbomEvidence,
    options::{CorrelationOptions, VersionlessMatchPolicy},
    types::{
        ComponentId, ComponentMatcher, ComponentQuery, MatchDimension, MatchEvidence,
        StatusAssertion, VersionConstraint,
    },
    version::version_matches,
};

pub(crate) fn queries_from_sbom(sbom: &SbomEvidence) -> Vec<ComponentQuery> {
    sbom.components
        .iter()
        .map(|component| ComponentQuery {
            id: component.id.clone(),
            context: component
                .context
                .iter()
                .chain(sbom.context.iter())
                .cloned()
                .collect(),
            grouping: component
                .grouping
                .iter()
                .chain(
                    sbom.grouping
                        .iter()
                        .filter(|group| group.subject == component.id),
                )
                .cloned()
                .collect(),
        })
        .collect()
}

pub(crate) fn matches_component(query: &ComponentQuery, assertion: &StatusAssertion) -> bool {
    if !assertion
        .context
        .iter()
        .all(|context| query.context.contains(context))
        || !assertion
            .grouping
            .iter()
            .all(|group| query.grouping.contains(group))
    {
        return false;
    }

    match (&query.id, &assertion.matcher) {
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
            comp_ty == match_ty
                && comp_ns == match_ns
                && comp_name == match_name
                && qualifiers_match(qualifiers, &query.id)
        }
        (ComponentId::Cpe(comp_cpe), ComponentMatcher::CpeMatch { cpe: match_cpe, .. }) => {
            cpe_prefix_matches(comp_cpe, match_cpe)
        }
        (
            ComponentId::Hash {
                algorithm: comp_algorithm,
                value: comp_value,
            },
            ComponentMatcher::Hash {
                algorithm: match_algorithm,
                value: match_value,
            },
        ) => comp_algorithm.eq_ignore_ascii_case(match_algorithm) && comp_value == match_value,
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

pub(crate) fn check_version(
    component: &ComponentId,
    assertion: &StatusAssertion,
    options: &CorrelationOptions,
) -> bool {
    let comp_version = match component {
        ComponentId::Purl {
            version: Some(v),
            ty,
            qualifiers,
            ..
        } => {
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
        ComponentId::Purl { version: None, .. } => {
            return versionless_component_allowed(&assertion.matcher, options);
        }
        ComponentId::Cpe(cpe) => match cpe_version(cpe) {
            Some(v) => v,
            None => return versionless_component_allowed(&assertion.matcher, options),
        },
        _ => return true,
    };

    let constraint = match &assertion.matcher {
        ComponentMatcher::Purl {
            version: Some(vc), ..
        } => vc,
        ComponentMatcher::Purl { version: None, .. } => {
            return match assertion.version_policy {
                crate::types::VersionPolicy::AnyVersion => true,
                crate::types::VersionPolicy::IdentityOnly => {
                    matches!(component, ComponentId::Purl { version: None, .. })
                }
            };
        }
        ComponentMatcher::CpeMatch {
            version: Some(vc), ..
        } => vc,
        ComponentMatcher::CpeMatch { version: None, .. } => return true,
        ComponentMatcher::CveProduct { version: vc, .. } => vc,
        ComponentMatcher::Hash { .. } => return true,
    };

    version_matches(&comp_version, &constraint.range, constraint.scheme)
}

fn versionless_component_allowed(matcher: &ComponentMatcher, options: &CorrelationOptions) -> bool {
    let constrained = matches!(
        matcher,
        ComponentMatcher::Purl {
            version: Some(_),
            ..
        } | ComponentMatcher::CpeMatch {
            version: Some(_),
            ..
        } | ComponentMatcher::CveProduct { .. }
    );

    !constrained || matches!(options.versionless_matches, VersionlessMatchPolicy::Allow)
}

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

fn cpe_version(cpe: &str) -> Option<String> {
    let parts = normalize_cpe(cpe);
    parts.get(5).filter(|v| v.as_str() != "*").cloned()
}

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

pub(crate) fn format_component_id(id: &ComponentId) -> String {
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

pub(crate) fn format_matcher(matcher: &ComponentMatcher) -> String {
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
        ComponentMatcher::Hash { algorithm, value } => format!("hash:{algorithm}:{value}"),
        ComponentMatcher::CveProduct { product, version } => {
            format!("product:{product} version={}", version.range)
        }
    }
}

pub(crate) fn explain_skip(component: &ComponentId, matcher: &ComponentMatcher) -> String {
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

pub(crate) fn match_dimension(matcher: &ComponentMatcher) -> MatchDimension {
    match matcher {
        ComponentMatcher::Purl { .. } => MatchDimension::Purl,
        ComponentMatcher::CpeMatch { .. } => MatchDimension::Cpe,
        ComponentMatcher::Hash { .. } => MatchDimension::Hash,
        ComponentMatcher::CveProduct { .. } => MatchDimension::Product,
    }
}

pub(crate) fn version_constraint(matcher: &ComponentMatcher) -> Option<VersionConstraint> {
    match matcher {
        ComponentMatcher::Purl { version, .. } | ComponentMatcher::CpeMatch { version, .. } => {
            version.clone()
        }
        ComponentMatcher::CveProduct { version, .. } => Some(version.clone()),
        ComponentMatcher::Hash { .. } => None,
    }
}

/// Build a [`MatchEvidence`] record for an assertion that matched a component.
///
/// Shared by the streaming `Collector::on_match` path and by the verdict's
/// retained evidence so both are constructed identically.
pub(crate) fn match_evidence(
    component: &ComponentId,
    assertion: &StatusAssertion,
    version_in_range: bool,
) -> MatchEvidence {
    MatchEvidence {
        component: component.clone(),
        assertion_source: assertion.source.clone(),
        vulnerability_id: assertion.vulnerability_id.clone(),
        status: assertion.status,
        dimension: match_dimension(&assertion.matcher),
        matcher: assertion.matcher.clone(),
        version_in_range: Some(version_in_range),
        version_constraint: version_constraint(&assertion.matcher),
        context: assertion.context.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{check_version, qualifiers_match};
    use crate::options::{CorrelationOptions, VersionlessMatchPolicy};
    use crate::types::{
        AdvisoryRef, AssertionStatus, ComponentId, ComponentMatcher, StatusAssertion,
        VersionConstraint, VersionPolicy,
    };
    use crate::version::{VersionRange, VersionScheme};
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
            &component(&[("distro", "rhel-10")])
        ));
        assert!(qualifiers_match(
            &expected,
            &component(&[("distro", "rhel-8"), ("arch", "x86_64")])
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

    #[test]
    fn versionless_component_rejects_constrained_assertion_by_default() {
        let assertion = StatusAssertion {
            source: AdvisoryRef {
                identifier: "CVE-test".into(),
                source_file: None,
            },
            vulnerability_id: "CVE-test".into(),
            status: AssertionStatus::Affected,
            version_policy: VersionPolicy::IdentityOnly,
            matcher: ComponentMatcher::Purl {
                ty: "rpm".into(),
                namespace: Some("redhat".into()),
                name: "openssl".into(),
                qualifiers: BTreeMap::new(),
                version: Some(VersionConstraint {
                    scheme: VersionScheme::Rpm,
                    range: VersionRange::Exact("3.0.0".into()),
                }),
            },
            context: Vec::new(),
            grouping: Vec::new(),
        };
        let component = ComponentId::Purl {
            ty: "rpm".into(),
            namespace: Some("redhat".into()),
            name: "openssl".into(),
            version: None,
            qualifiers: BTreeMap::new(),
        };

        assert!(!check_version(
            &component,
            &assertion,
            &CorrelationOptions::default()
        ));
        assert!(check_version(
            &component,
            &assertion,
            &CorrelationOptions {
                versionless_matches: VersionlessMatchPolicy::Allow,
            }
        ));
    }

    #[test]
    fn bare_affected_purl_applies_to_versioned_component() {
        let matcher = ComponentMatcher::Purl {
            ty: "rpm".into(),
            namespace: Some("redhat".into()),
            name: "openssl".into(),
            qualifiers: BTreeMap::new(),
            version: None,
        };
        let assertion = StatusAssertion {
            source: AdvisoryRef {
                identifier: "CVE-test".into(),
                source_file: None,
            },
            vulnerability_id: "CVE-test".into(),
            status: AssertionStatus::Affected,
            version_policy: VersionPolicy::AnyVersion,
            matcher,
            context: Vec::new(),
            grouping: Vec::new(),
        };
        let component = ComponentId::Purl {
            ty: "rpm".into(),
            namespace: Some("redhat".into()),
            name: "openssl".into(),
            version: Some("3.0.0".into()),
            qualifiers: BTreeMap::new(),
        };
        assert!(check_version(
            &component,
            &assertion,
            &CorrelationOptions::default()
        ));
    }
}
