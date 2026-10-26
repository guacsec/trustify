mod prefix;

pub mod loader;
pub mod translate;

use crate::{graph::cvss::ScoreCreator, service::Error};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use osv::schema::{SeverityType, Vulnerability};
use std::{collections::BTreeSet, str::FromStr};

/// Load a [`Vulnerability`] from YAML.
pub fn from_yaml(data: &[u8]) -> Result<Vulnerability, serde_saphyr::Error> {
    serde_saphyr::from_slice(data)
}

/// Serialize a [`Vulnerability`] as YAML.
pub fn to_yaml(vuln: &Vulnerability) -> Result<String, serde_saphyr::SerializeError> {
    serde_saphyr::to_string(vuln)
}

/// Parse an OSV document into a [`Vulnerability`].
pub fn parse(buffer: &[u8]) -> Result<Vulnerability, Error> {
    let osv: Vulnerability = serde_json::from_slice(buffer)
        .map_err(Error::from)
        .or_else(|_| from_yaml(buffer).map_err(Error::from))?;

    Ok(osv)
}

/// Extract CVEs described by this advisory, including upstream vulnerabilities
/// referenced by distribution advisories. This links advisory/package status to
/// the CVE; it does not treat upstream IDs as symmetric aliases.
pub fn extract_vulnerability_ids(osv: &Vulnerability) -> impl Iterator<Item = &str> {
    osv.aliases
        .iter()
        .chain(osv.upstream.iter())
        .flatten()
        .filter(|id| id.starts_with("CVE-"))
        .map(|s| s.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
}

/// extract scores from OSV
pub fn extract_scores(osv: &Vulnerability, creator: &mut ScoreCreator) {
    // Get all vulnerability IDs upfront
    let ids: Vec<_> = extract_vulnerability_ids(osv).collect();

    // If no vulnerability IDs, nothing to do
    if ids.is_empty() {
        return;
    }

    // Process each severity entry
    for severity in osv.severity.iter().flatten() {
        match severity.severity_type {
            SeverityType::CVSSv2 => match CvssV2::from_str(&severity.score) {
                Ok(cvss) => {
                    for id in &ids {
                        creator.add((id.to_string(), cvss.clone()));
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse CVSSv2 vector '{}': {:?}",
                        severity.score,
                        e
                    );
                }
            },

            SeverityType::CVSSv3 => match CvssV3::from_str(&severity.score) {
                Ok(cvss) => {
                    for id in &ids {
                        creator.add((id.to_string(), cvss.clone()));
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse CVSSv3 vector '{}': {:?}",
                        severity.score,
                        e
                    );
                }
            },

            SeverityType::CVSSv4 => match CvssV4::from_str(&severity.score) {
                Ok(cvss) => {
                    for id in &ids {
                        creator.add((id.to_string(), cvss.clone()));
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse CVSSv4 vector '{}': {:?}",
                        severity.score,
                        e
                    );
                }
            },

            _ => {
                // Unknown severity type, skip
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_cves_are_linked_without_duplicate_aliases() {
        let osv = parse(br#"{
            "id":"CGA-2222-2222-2222", "modified":"2026-01-01T00:00:00Z",
            "aliases":["CVE-2025-1234", "GHSA-example"],
            "upstream":["CVE-2025-1234", "CVE-2025-5678"],
            "related":["CVE-2025-9999"],
            "schema_version":"1.7.5", "severity":null, "references":null,
            "affected":[{
                "package": {"ecosystem":"Chainguard", "name":"curl", "purl":"pkg:apk/chainguard/curl?arch=x86_64"},
                "ranges":[{"type":"ECOSYSTEM", "events":[{"introduced":"0"},{"fixed":"8.4.0-r0"}]}],
                "ecosystem_specific":{"components":[{"latest_event_status":"fixed", "component_name":"curl"}]}
            }]
        }"#).unwrap();
        assert_eq!(
            extract_vulnerability_ids(&osv).collect::<Vec<_>>(),
            ["CVE-2025-1234", "CVE-2025-5678"]
        );
        assert_eq!(
            osv.affected.as_ref().unwrap()[0]
                .package
                .as_ref()
                .unwrap()
                .purl
                .as_deref(),
            Some("pkg:apk/chainguard/curl?arch=x86_64")
        );
    }
}
