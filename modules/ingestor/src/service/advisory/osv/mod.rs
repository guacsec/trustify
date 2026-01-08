mod prefix;

pub mod loader;
pub mod translate;

use crate::{graph::cvss::ScoreCreator, service::Error};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use osv::schema::{SeverityType, Vulnerability};
use std::str::FromStr;

/// Load a [`Vulnerability`] from YAML, using the "classic" enum representation.
pub fn from_yaml(data: &[u8]) -> Result<Vulnerability, serde_yml::Error> {
    #[derive(serde::Deserialize)]
    struct VulnerabilityWrapped(
        #[serde(with = "serde_yml::with::singleton_map_recursive")] Vulnerability,
    );

    serde_yml::from_slice::<VulnerabilityWrapped>(data).map(|osv| osv.0)
}

/// Serialize a [`Vulnerability`] as YAML, using the "classic" enum representation.
pub fn to_yaml(vuln: &Vulnerability) -> Result<String, serde_yml::Error> {
    #[derive(serde::Serialize)]
    struct VulnerabilityWrapped<'a>(
        #[serde(with = "serde_yml::with::singleton_map_recursive")] &'a Vulnerability,
    );

    serde_yml::to_string(&VulnerabilityWrapped(vuln))
}

/// Parse an OSV document into a [`Vulnerability`].
pub fn parse(buffer: &[u8]) -> Result<Vulnerability, Error> {
    let osv: Vulnerability = serde_json::from_slice(buffer)
        .map_err(Error::from)
        .or_else(|_| from_yaml(buffer).map_err(Error::from))?;

    Ok(osv)
}

/// extract vulnerability IDs
pub fn extract_vulnerability_ids(osv: &Vulnerability) -> impl IntoIterator<Item = &str> {
    osv.aliases
        .iter()
        .flat_map(|aliases| aliases.iter().filter(|e| e.starts_with("CVE-")))
        .map(|s| s.as_str())
}

/// extract scores from OSV
pub fn extract_scores(osv: &Vulnerability, creator: &mut ScoreCreator) {
    // Get all vulnerability IDs upfront
    let ids: Vec<_> = extract_vulnerability_ids(osv).into_iter().collect();

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
