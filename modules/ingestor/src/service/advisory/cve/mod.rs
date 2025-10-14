use crate::graph::cvss::ScoreCreator;
use cve::Cve;
use cvss::{Cvss, v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};

pub mod divination;
pub mod loader;

pub fn extract_scores(cve: &Cve, _score_creator: &mut ScoreCreator) {
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

    for metric in all_metrics {
        let cvss_objects: Vec<Cvss> = [
            metric.cvss_v2_0.as_ref().and_then(|v| {
                serde_json::from_value::<CvssV2>(v.clone())
                    .ok()
                    .map(Cvss::V2)
            }),
            metric.cvss_v3_0.as_ref().and_then(|v| {
                serde_json::from_value::<CvssV3>(v.clone())
                    .ok()
                    .map(Cvss::V3_0)
            }),
            metric.cvss_v3_1.as_ref().and_then(|v| {
                serde_json::from_value::<CvssV3>(v.clone())
                    .ok()
                    .map(Cvss::V3_1)
            }),
            metric.cvss_v4_0.as_ref().and_then(|v| {
                serde_json::from_value::<CvssV4>(v.clone())
                    .ok()
                    .map(Cvss::V4)
            }),
        ]
        .into_iter()
        .flatten()
        .collect();

        for cvss in cvss_objects {
            println!("Parsed CVSS: {:?}", cvss);
        }
    }
}
