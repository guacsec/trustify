use crate::types::{AdvisoryRef, ComponentMatcher, Status, StatusAssertion, VersionConstraint};
use crate::version::{VersionBound, VersionRange, VersionScheme};

/// Extract status assertions from a CVE 5.x record.
pub fn extract(source_file: &str, doc: &serde_json::Value) -> Vec<StatusAssertion> {
    let cve_id = doc
        .pointer("/cveMetadata/cveId")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let advisory_ref = AdvisoryRef {
        identifier: cve_id.to_string(),
        source_file: Some(source_file.to_string()),
    };

    let mut assertions = Vec::new();

    // Process CNA container
    if let Some(cna) = doc.pointer("/containers/cna") {
        extract_from_container(cve_id, &advisory_ref, cna, &mut assertions);
    }

    // Process ADP containers
    if let Some(adp_arr) = doc.pointer("/containers/adp").and_then(|v| v.as_array()) {
        for adp in adp_arr {
            extract_from_container(cve_id, &advisory_ref, adp, &mut assertions);
        }
    }

    assertions
}

fn extract_from_container(
    cve_id: &str,
    advisory_ref: &AdvisoryRef,
    container: &serde_json::Value,
    assertions: &mut Vec<StatusAssertion>,
) {
    let Some(affected_arr) = container.get("affected").and_then(|v| v.as_array()) else {
        return;
    };

    for affected in affected_arr {
        // Extract CPE-based assertions (defaultStatus + cpes)
        if let Some(cpes) = affected.get("cpes").and_then(|v| v.as_array()) {
            let default_status = affected
                .get("defaultStatus")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let status = match default_status {
                "affected" => Some(Status::Affected),
                "unaffected" => Some(Status::NotAffected),
                _ => None,
            };

            if let Some(status) = status {
                for cpe_val in cpes {
                    if let Some(cpe) = cpe_val.as_str() {
                        assertions.push(StatusAssertion {
                            source: advisory_ref.clone(),
                            vulnerability_id: cve_id.to_string(),
                            status,
                            matcher: ComponentMatcher::CpeMatch {
                                cpe: cpe.to_string(),
                                version: None,
                            },
                        });
                    }
                }
            }
        }

        let product = affected.get("product").and_then(|v| v.as_str());
        let Some(versions) = affected.get("versions").and_then(|v| v.as_array()) else {
            continue;
        };

        let Some(product_name) = product else {
            continue;
        };

        for ver in versions {
            let status_str = ver
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let status = match status_str {
                "affected" => Status::Affected,
                "unaffected" => Status::NotAffected,
                _ => continue,
            };

            let version_type = ver
                .get("versionType")
                .and_then(|v| v.as_str())
                .unwrap_or("custom");

            let scheme = VersionScheme::from(version_type);

            let start_version = ver.get("version").and_then(|v| v.as_str());
            let less_than = ver.get("lessThan").and_then(|v| v.as_str());
            let less_than_eq = ver.get("lessThanOrEqual").and_then(|v| v.as_str());

            let range = match (start_version, less_than, less_than_eq) {
                (Some(start), Some(lt), _) => VersionRange::Range(
                    VersionBound::Inclusive(start.to_string()),
                    VersionBound::Exclusive(lt.to_string()),
                ),
                (Some(start), _, Some(lte)) => VersionRange::Range(
                    VersionBound::Inclusive(start.to_string()),
                    VersionBound::Inclusive(lte.to_string()),
                ),
                (Some(ver), None, None) => VersionRange::Exact(ver.to_string()),
                _ => continue,
            };

            assertions.push(StatusAssertion {
                source: advisory_ref.clone(),
                vulnerability_id: cve_id.to_string(),
                status,
                matcher: ComponentMatcher::CveProduct {
                    product: product_name.to_string(),
                    version: VersionConstraint { scheme, range },
                },
            });
        }
    }
}
