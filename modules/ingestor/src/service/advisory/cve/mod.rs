use crate::graph::cvss::ScoreInformation;
use cve::Cve;
use cvss::{Cvss, v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};

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

/// Extracts all CVSS scores from a CVE record.
///
/// Processes metrics from both CNA and ADP containers. All parseable CVSS scores (v2, v3, v4)
/// are returned, keyed by the CVE identifier. Rejected CVEs produce an empty vec.
pub fn extract_scores(cve: &Cve) -> Vec<ScoreInformation> {
    let Cve::Published(published) = cve else {
        return Vec::new();
    };

    let vulnerability_id = &published.metadata.id;

    let all_metrics = published.containers.cna.metrics.iter().chain(
        published
            .containers
            .adp
            .iter()
            .flat_map(|adp| adp.metrics.iter()),
    );

    let mut scores = Vec::new();
    for cve_metric in all_metrics {
        let metric = CvssMetric::from(cve_metric);

        for cvss in [
            metric.cvss_v2_0.map(Cvss::V2),
            metric.cvss_v3_0.map(Cvss::V3_0),
            metric.cvss_v3_1.map(Cvss::V3_1),
            metric.cvss_v4_0.map(Cvss::V4),
        ]
        .into_iter()
        .flatten()
        {
            scores.push(ScoreInformation::from((vulnerability_id.clone(), cvss)));
        }
    }

    scores
}
