use crate::graph::cvss::ScoreCreator;
use cve::Cve;
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};

pub mod divination;
pub mod loader;

pub fn extract_scores(cve: &Cve, creator: &mut ScoreCreator) {
    let Cve::Published(published) = cve else {
        return;
    };

    let all_metrics = published.containers.cna.metrics.iter().chain(
        published
            .containers
            .adp
            .iter()
            .flat_map(|adp| adp.metrics.iter()),
    );

    let vulnerability_id = &published.metadata.id;

    for metric in all_metrics {
        if let Some(v) = &metric.cvss_v2_0
            && let Ok(score) = serde_json::from_value::<CvssV2>(v.clone())
        {
            creator.add((vulnerability_id.clone(), score));
        }

        if let Some(v) = &metric.cvss_v3_0
            && let Ok(score) = serde_json::from_value::<CvssV3>(v.clone())
        {
            creator.add((vulnerability_id.clone(), score));
        }

        if let Some(v) = &metric.cvss_v3_1
            && let Ok(score) = serde_json::from_value::<CvssV3>(v.clone())
        {
            creator.add((vulnerability_id.clone(), score));
        }

        if let Some(v) = &metric.cvss_v4_0
            && let Ok(score) = serde_json::from_value::<CvssV4>(v.clone())
        {
            creator.add((vulnerability_id.clone(), score));
        }
    }
}
