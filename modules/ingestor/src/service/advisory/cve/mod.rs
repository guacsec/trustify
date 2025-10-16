use crate::graph::cvss::ScoreCreator;
use cve::Cve;
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4, Cvss};

pub mod divination;
pub mod loader;

#[derive(Clone, Debug, PartialEq, Default)]
struct CvssMetric {
    pub cvss_v2_0: Option<CvssV2>,
    pub cvss_v3_0: Option<CvssV3>,
    pub cvss_v3_1: Option<CvssV3>,
    pub cvss_v4_0: Option<CvssV4>,
}

impl From<&cve::published::Metric> for CvssMetric {
    fn from(metric: &cve::published::Metric) -> Self {
        Self {
            cvss_v2_0: metric
                .cvss_v2_0
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            cvss_v3_0: metric
                .cvss_v3_0
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            cvss_v3_1: metric
                .cvss_v3_1
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            cvss_v4_0: metric
                .cvss_v4_0
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
        }
    }
}

pub fn extract_scores(cve: &Cve, creator: &mut ScoreCreator) {
    let Cve::Published(published) = cve else {
        return;
    };

    let vulnerability_id = &published.metadata.id;

    let all_metrics = published.containers.cna.metrics.iter().chain(
        published
            .containers
            .adp
            .iter()
            .flat_map(|adp| adp.metrics.iter()),
    );

    for cve_metric in all_metrics {
        let metric = CvssMetric::from(cve_metric);

        let cvss_objects: Vec<Cvss> = vec![
            metric.cvss_v3_1.map(Cvss::V3_1),
            metric.cvss_v3_0.map(Cvss::V3_0),
            metric.cvss_v2_0.map(Cvss::V2),
            metric.cvss_v4_0.map(Cvss::V4),
        ]
        .into_iter()
        .flatten()
        .collect();

        for score in cvss_objects {
            creator.add((vulnerability_id.clone(), score));
        }
    }
}
