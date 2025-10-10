mod prefix;

pub mod loader;
pub mod translate;

use crate::{graph::cvss::ScoreCreator, service::Error};
use osv::schema::{SeverityType, Vulnerability};
use sea_orm::{NotSet, Set};
use trustify_entity::advisory_vulnerability_score::{self, ScoreType};
use uuid::Uuid;

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
    // TODO: validate score type by prefix
    let scores = osv
        .severity
        .iter()
        .flatten()
        .flat_map(|severity| match severity.severity_type {
            SeverityType::CVSSv2 => Some((
                ScoreType::V2_0,
                severity.score.clone(),
                10f64, // TODO: replace with actual evaluated score
                advisory_vulnerability_score::Severity::Critical, // TODO: replace with actual evaluated severity
            )),
            SeverityType::CVSSv3 => Some((
                match severity.score.starts_with("CVSS:3.1/") {
                    true => ScoreType::V3_1,
                    false => ScoreType::V3_0,
                },
                severity.score.clone(),
                10f64, // TODO: replace with actual evaluated score
                advisory_vulnerability_score::Severity::Critical, // TODO: replace with actual evaluated severity
            )),
            SeverityType::CVSSv4 => Some((
                ScoreType::V4_0,
                severity.score.clone(),
                10f64, // TODO: replace with actual evaluated score
                advisory_vulnerability_score::Severity::Critical, // TODO: replace with actual evaluated severity
            )),

            _ => None,
        })
        .map(
            move |(r#type, vector, score, severity)| advisory_vulnerability_score::ActiveModel {
                id: Set(Uuid::now_v7()),
                r#type: Set(r#type),
                vector: Set(vector),
                score: Set(score),
                severity: Set(severity),
                advisory_id: NotSet,
                vulnerability_id: NotSet,
            },
        );

    // get all vulnerability IDs

    let ids = extract_vulnerability_ids(osv)
        .into_iter()
        .collect::<Vec<_>>();

    // create scores for each vulnerability (alias)

    creator.extend(scores.into_iter().flat_map(|score| {
        ids.iter().map(move |id| {
            let mut score = score.clone();
            score.vulnerability_id = Set(id.to_string());
            score
        })
    }));
}
