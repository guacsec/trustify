mod ecosystem;
mod prefix;

pub mod loader;
pub mod translate;

use crate::{graph::cvss::ScoreCreator, service::Error};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use osv::schema::{Ecosystem, SeverityType, Vulnerability};
use std::{collections::HashSet, str::FromStr};

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

/// Extract the vulnerability (CVE) IDs an OSV record is linked to.
///
/// These are the `CVE-` entries of `aliases`. Red Hat Lightwell records list their CVEs in
/// `upstream` instead, so for records with any Lightwell package the `CVE-` entries of
/// `upstream` are included too. Duplicates are removed, keeping first-seen order.
pub fn extract_vulnerability_ids(osv: &Vulnerability) -> Vec<&str> {
    let lightwell = osv
        .affected
        .iter()
        .flatten()
        .filter_map(|affected| affected.package.as_ref())
        .any(|package| matches!(package.ecosystem, Ecosystem::RedHatLightwell(_)));
    let upstream = osv.upstream.iter().flatten().filter(|_| lightwell);

    let mut seen = HashSet::new();
    osv.aliases
        .iter()
        .flatten()
        .chain(upstream)
        .map(String::as_str)
        .filter(|id| id.starts_with("CVE-") && seen.insert(*id))
        .collect()
}

/// extract scores from OSV
pub fn extract_scores(osv: &Vulnerability, creator: &mut ScoreCreator) {
    // Get all vulnerability IDs upfront
    let ids = extract_vulnerability_ids(osv);

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
mod test {
    use super::*;
    use rstest::rstest;

    /// Verifies which `aliases` and `upstream` entries are used as vulnerability IDs.
    #[rstest]
    #[case::ordinary_aliases("PyPI", Some(&["CVE-1", "GHSA-1"][..]), None, &["CVE-1"][..])]
    #[case::ordinary_upstream_only("PyPI", None, Some(&["CVE-1"][..]), &[][..])]
    #[case::lightwell_upstream_only(
        "Red Hat Lightwell:PyPI",
        None,
        Some(&["CVE-1", "GHSA-1"][..]),
        &["CVE-1"][..]
    )]
    #[case::lightwell_deduplicated(
        "Red Hat Lightwell:Maven",
        Some(&["CVE-2", "CVE-1"][..]),
        Some(&["CVE-1", "CVE-3", "CVE-2"][..]),
        &["CVE-2", "CVE-1", "CVE-3"][..]
    )]
    fn vulnerability_ids(
        #[case] ecosystem: &str,
        #[case] aliases: Option<&[&str]>,
        #[case] upstream: Option<&[&str]>,
        #[case] expected: &[&str],
    ) -> anyhow::Result<()> {
        let osv: Vulnerability = serde_json::from_value(serde_json::json!({
            "id": "TEST-1",
            "modified": "2026-01-01T00:00:00Z",
            "aliases": aliases,
            "upstream": upstream,
            "affected": [{"package": {"ecosystem": ecosystem, "name": "example"}}],
        }))?;
        assert_eq!(extract_vulnerability_ids(&osv), expected);
        Ok(())
    }
}
