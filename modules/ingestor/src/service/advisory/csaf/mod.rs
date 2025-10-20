pub mod loader;
mod product_status;
mod util;

mod creator;
pub use creator::*;

use crate::graph::cvss::{ScoreCreator, ScoreInformation};
use csaf::Csaf;
use trustify_entity::advisory_vulnerability_score::ScoreType;

/// Extract scores from a CSAF document
pub fn extract_scores(csaf: &Csaf, creator: &mut ScoreCreator) {
    for vuln in csaf.vulnerabilities.iter().flatten() {
        let Some(vulnerability_id) = &vuln.cve else {
            // we only process CVEs
            continue;
        };

        for score in vuln.scores.iter().flatten() {
            if let Some(score) = &score.cvss_v2 {
                if let Ok(score) = serde_json::from_value::<cvss::v2_0::CvssV2>(score.clone()) {
                    creator.add((vulnerability_id.clone(), score))
                }
            }

            if let Some(score) = &score.cvss_v3 {
                // TODO: maybe use raw values from JSON
                let vector = score.to_string();
                let score = score.score();
                creator.add(ScoreInformation {
                    vulnerability_id: vulnerability_id.clone(),
                    r#type: ScoreType::V3_0,
                    vector,
                    score: score.value(),
                    severity: score.severity().into(),
                })
            }
        }
    }
}
