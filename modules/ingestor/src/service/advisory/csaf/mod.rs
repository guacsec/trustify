pub mod loader;
mod product_status;
pub mod util;

mod creator;
pub use creator::*;

use crate::graph::cvss::ScoreCreator;
use csaf_rs::schema::csaf2_0::schema::CommonSecurityAdvisoryFramework as Csaf;
use cvss::v3::CvssV3;

/// Extract scores from a CSAF document
pub fn extract_scores(csaf: &Csaf, creator: &mut ScoreCreator) {
    for vuln in &csaf.vulnerabilities {
        let Some(vulnerability_id) = &vuln.cve else {
            // we only process CVEs
            continue;
        };

        for score in &vuln.scores {
            if let Ok(score) = serde_json::from_value::<cvss::v2_0::CvssV2>(
                serde_json::Value::Object(score.cvss_v2.clone()),
            ) {
                creator.add((vulnerability_id.to_string(), score))
            }

            if let Ok(cvss) =
                serde_json::from_value::<CvssV3>(serde_json::Value::Object(score.cvss_v3.clone()))
            {
                creator.add((vulnerability_id.to_string(), cvss))
            }
        }
    }
}
