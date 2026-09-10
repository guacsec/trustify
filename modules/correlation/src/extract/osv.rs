use crate::types::{
    AdvisoryRef, ComponentMatcher, Status, StatusAssertion, VersionConstraint, parse_purl,
};
use crate::version::{VersionBound, VersionRange, VersionScheme};

/// Extract status assertions from an OSV advisory.
pub fn extract(source_file: &str, doc: &serde_json::Value) -> Vec<StatusAssertion> {
    let osv_id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");

    let advisory_ref = AdvisoryRef {
        identifier: osv_id.to_string(),
        source_file: Some(source_file.to_string()),
    };

    // Use CVE alias as vulnerability_id if available, otherwise use OSV id
    let vuln_id = doc
        .get("aliases")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .find(|s| s.starts_with("CVE-"))
        })
        .unwrap_or(osv_id);

    let mut assertions = Vec::new();

    let Some(affected_arr) = doc.get("affected").and_then(|v| v.as_array()) else {
        return assertions;
    };

    for affected in affected_arr {
        let package = match affected.get("package") {
            Some(p) => p,
            None => continue,
        };

        let purl_str = package.get("purl").and_then(|v| v.as_str());
        let ecosystem = package.get("ecosystem").and_then(|v| v.as_str());

        // Determine base PURL matcher
        let (ty, namespace, name, qualifiers) = if let Some(purl_str) = purl_str {
            match parse_purl(purl_str) {
                Some(crate::types::ComponentId::Purl {
                    ty,
                    namespace,
                    name,
                    qualifiers,
                    ..
                }) => (ty, namespace, name, qualifiers),
                _ => continue,
            }
        } else {
            continue;
        };

        let scheme = match ecosystem {
            Some(e) => VersionScheme::from(ecosystem_to_scheme(e)),
            None => VersionScheme::Semver,
        };

        let Some(ranges) = affected.get("ranges").and_then(|v| v.as_array()) else {
            continue;
        };

        for range in ranges {
            let Some(events) = range.get("events").and_then(|v| v.as_array()) else {
                continue;
            };

            // Parse events into (introduced, fixed) pairs
            let mut introduced: Option<String> = None;

            for event in events {
                if let Some(intro) = event.get("introduced").and_then(|v| v.as_str()) {
                    introduced = Some(intro.to_string());
                }

                if let Some(fixed) = event.get("fixed").and_then(|v| v.as_str()) {
                    let low = match &introduced {
                        Some(v) if v == "0" => VersionBound::Unbounded,
                        Some(v) => VersionBound::Inclusive(v.clone()),
                        None => VersionBound::Unbounded,
                    };

                    assertions.push(StatusAssertion {
                        source: advisory_ref.clone(),
                        vulnerability_id: vuln_id.to_string(),
                        status: Status::Affected,
                        matcher: ComponentMatcher::Purl {
                            ty: ty.clone(),
                            namespace: namespace.clone(),
                            name: name.clone(),
                            qualifiers: qualifiers.clone(),
                            version: Some(VersionConstraint {
                                scheme,
                                range: VersionRange::Range(
                                    low,
                                    VersionBound::Exclusive(fixed.to_string()),
                                ),
                            }),
                            context_cpe: None,
                        },
                    });

                    introduced = None;
                }

                if let Some(last_affected) = event.get("last_affected").and_then(|v| v.as_str()) {
                    let low = match &introduced {
                        Some(v) if v == "0" => VersionBound::Unbounded,
                        Some(v) => VersionBound::Inclusive(v.clone()),
                        None => VersionBound::Unbounded,
                    };

                    assertions.push(StatusAssertion {
                        source: advisory_ref.clone(),
                        vulnerability_id: vuln_id.to_string(),
                        status: Status::Affected,
                        matcher: ComponentMatcher::Purl {
                            ty: ty.clone(),
                            namespace: namespace.clone(),
                            name: name.clone(),
                            qualifiers: qualifiers.clone(),
                            version: Some(VersionConstraint {
                                scheme,
                                range: VersionRange::Range(
                                    low,
                                    VersionBound::Inclusive(last_affected.to_string()),
                                ),
                            }),
                            context_cpe: None,
                        },
                    });

                    introduced = None;
                }
            }

            // If introduced but no fixed → open-ended affected range
            if let Some(intro) = introduced {
                let low = if intro == "0" {
                    VersionBound::Unbounded
                } else {
                    VersionBound::Inclusive(intro)
                };

                assertions.push(StatusAssertion {
                    source: advisory_ref.clone(),
                    vulnerability_id: vuln_id.to_string(),
                    status: Status::Affected,
                    matcher: ComponentMatcher::Purl {
                        ty: ty.clone(),
                        namespace: namespace.clone(),
                        name: name.clone(),
                        qualifiers: qualifiers.clone(),
                        version: Some(VersionConstraint {
                            scheme,
                            range: VersionRange::Range(low, VersionBound::Unbounded),
                        }),
                        context_cpe: None,
                    },
                });
            }
        }
    }

    assertions
}

fn ecosystem_to_scheme(ecosystem: &str) -> &str {
    match ecosystem {
        "PyPI" => "python",
        "Maven" => "maven",
        "npm" => "npm",
        "Go" => "golang",
        "RubyGems" => "gem",
        "NuGet" => "nuget",
        "Packagist" => "packagist",
        "Hex" => "hex",
        "Pub" => "pub",
        "SwiftURL" => "swift",
        "crates.io" => "cargo",
        _ => "semver",
    }
}
