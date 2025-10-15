mod prefix;

pub mod loader;
pub mod translate;

use crate::{
    graph::cvss::{ScoreCreator, ScoreInformation},
    service::Error,
};
use osv::schema::{SeverityType, Vulnerability};
use trustify_entity::advisory_vulnerability_score::{ScoreType, Severity};

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
    #[derive(Clone)]
    struct ScoreInfo {
        pub r#type: ScoreType,
        pub vector: String,
        pub score: f64,
        pub severity: Severity,
    }

    impl From<(String, ScoreInfo)> for ScoreInformation {
        fn from(
            (
                vulnerability_id,
                ScoreInfo {
                    r#type,
                    vector,
                    score,
                    severity,
                },
            ): (String, ScoreInfo),
        ) -> Self {
            Self {
                vulnerability_id,
                r#type,
                vector,
                score,
                severity,
            }
        }
    }

    // TODO: validate score type by prefix
    let scores = osv
        .severity
        .iter()
        .flatten()
        .flat_map(|severity| match severity.severity_type {
            SeverityType::CVSSv2 => Some(ScoreInfo {
                r#type: ScoreType::V2_0,
                vector: severity.score.clone(),
                score: 10f64, // TODO: replace with actual evaluated score
                severity: Severity::Critical, // TODO: replace with actual evaluated severity
            }),
            SeverityType::CVSSv3 => Some(ScoreInfo {
                r#type: match severity.score.starts_with("CVSS:3.1/") {
                    true => ScoreType::V3_1,
                    false => ScoreType::V3_0,
                },
                vector: severity.score.clone(),
                score: 10f64, // TODO: replace with actual evaluated score
                severity: Severity::Critical, // TODO: replace with actual evaluated severity
            }),
            SeverityType::CVSSv4 => Some(ScoreInfo {
                r#type: ScoreType::V4_0,
                vector: severity.score.clone(),
                score: 10f64, // TODO: replace with actual evaluated score
                severity: Severity::Critical, // TODO: replace with actual evaluated severity
            }),

            _ => None,
        });

    // get all vulnerability IDs

    let ids = extract_vulnerability_ids(osv)
        .into_iter()
        .collect::<Vec<_>>();

    // create scores for each vulnerability (alias)

    creator.extend(
        scores
            .into_iter()
            .flat_map(|score| ids.iter().map(move |id| (id.to_string(), score.clone()))),
    );
}
