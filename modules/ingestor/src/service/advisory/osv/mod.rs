mod prefix;

pub mod loader;
pub mod translate;

use crate::{graph::cvss::ScoreCreator, service::Error};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use osv::schema::{SeverityType, Vulnerability};
use std::str::FromStr;

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

/// Extract the IDs of the vulnerabilities of a record: its CVE aliases, or the record's own ID if
/// it has none.
///
/// The aliases are the IDs of the same vulnerability in other databases, so with a CVE alias, the
/// record is about that CVE. Without one, the record's ID is the only ID of the vulnerability.
pub fn extract_vulnerability_ids(osv: &Vulnerability) -> Vec<&str> {
    let cves = osv
        .aliases
        .iter()
        .flatten()
        .filter(|alias| alias.starts_with("CVE-"))
        .map(String::as_str)
        .collect::<Vec<_>>();

    match cves.is_empty() {
        true => vec![osv.id.as_str()],
        false => cves,
    }
}

/// extract scores from OSV
pub fn extract_scores(osv: &Vulnerability, creator: &mut ScoreCreator) {
    // Get all vulnerability IDs upfront
    let ids = extract_vulnerability_ids(osv);

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
                    tracing::warn!(
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
                    tracing::warn!(
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
                    tracing::warn!(
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
