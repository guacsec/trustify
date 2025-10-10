use crate::graph::cvss::ScoreCreator;
use cve::Cve;

pub mod divination;
pub mod loader;

pub fn extract_scores(cve: &Cve, score_creator: &mut ScoreCreator) {
    let Cve::Published(cve) = cve else {
        return;
    };

    for metrics in &cve.containers.cna.metrics {
        if let Some(value) = &metrics.cvss_v2_0 {
            // TODO: add score to creator
        }
        if let Some(value) = &metrics.cvss_v3_0 {
            // TODO: add score to creator
        }
        if let Some(value) = &metrics.cvss_v3_1 {
            // TODO: add score to creator
        }
        if let Some(value) = &metrics.cvss_v4_0 {
            // TODO: add score to creator
        }
    }
}
