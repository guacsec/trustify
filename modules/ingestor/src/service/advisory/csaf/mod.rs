pub mod loader;
mod product_status;
mod util;

mod creator;
pub use creator::*;

use crate::graph::cvss::ScoreCreator;
use csaf::Csaf;
use cvss::v3::CvssV3;

/// Extract scores from a CSAF document
pub fn extract_scores(csaf: &Csaf, creator: &mut ScoreCreator) {
    for vuln in csaf.vulnerabilities.iter().flatten() {
        let Some(vulnerability_id) = &vuln.cve else {
            // we only process CVEs
            continue;
        };

        for score in vuln.scores.iter().flatten() {
            if let Some(score) = &score.cvss_v2
                && let Ok(score) = serde_json::from_value::<cvss::v2_0::CvssV2>(score.clone())
            {
                creator.add((vulnerability_id.clone(), score))
            }

            if let Some(cvss_v3) = &score.cvss_v3
                && let Ok(cvss) = serde_json::from_value::<CvssV3>(cvss_v3.clone())
            {
                creator.add((vulnerability_id.clone(), cvss))
            }
        }
    }
}
