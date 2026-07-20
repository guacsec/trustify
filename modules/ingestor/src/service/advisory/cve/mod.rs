use crate::graph::{cvss::ScoreCreator, vulnerability::BaseScore};
use cve::Cve;
use cvss::{Cvss, v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4};
use serde_json::Value;
use std::str::FromStr;
use trustify_entity::advisory_vulnerability_score::{ScoreType, Severity};

pub mod divination;
pub mod loader;

/// Parses all CVSS objects from a single CVE metric entry by extracting the vector string
/// and parsing it with the appropriate version's `FromStr` impl. Returns one `Cvss` variant
/// per successfully parsed version field.
fn parse_cvss_from_metric(metric: &cve::published::Metric) -> Vec<Cvss> {
    let mut result = Vec::with_capacity(1);

    if let Some(cvss) = metric
        .cvss_v4_0
        .as_ref()
        .and_then(parse_from_vector_string::<CvssV4>)
    {
        result.push(Cvss::V4(cvss));
    }

    if let Some(cvss) = metric
        .cvss_v3_1
        .as_ref()
        .and_then(parse_from_vector_string::<CvssV3>)
    {
        result.push(Cvss::V3_1(cvss));
    }

    if let Some(cvss) = metric
        .cvss_v3_0
        .as_ref()
        .and_then(parse_from_vector_string::<CvssV3>)
    {
        result.push(Cvss::V3_0(cvss));
    }

    if let Some(cvss) = metric
        .cvss_v2_0
        .as_ref()
        .and_then(parse_from_vector_string::<CvssV2>)
    {
        result.push(Cvss::V2(cvss));
    }

    result
}

/// Extracts a `vectorString` from a JSON value and parses it via `FromStr`.
fn parse_from_vector_string<T: FromStr>(value: &Value) -> Option<T> {
    value
        .get("vectorString")
        .and_then(Value::as_str)
        .and_then(|s| T::from_str(s).ok())
}

/// Computes a [`BaseScore`] from a parsed CVSS object using `calculated_base_score()`.
fn base_score_from_cvss(cvss: &Cvss) -> Option<BaseScore> {
    let (score, score_type) = match cvss {
        Cvss::V4(c) => (c.calculated_base_score()?, ScoreType::V4_0),
        Cvss::V3_1(c) | Cvss::V3_0(c) => {
            let score_type = match c.version {
                Some(cvss::version::VersionV3::V3_1) => ScoreType::V3_1,
                _ => ScoreType::V3_0,
            };
            (c.calculated_base_score()?, score_type)
        }
        Cvss::V2(c) => (c.calculated_base_score()?, ScoreType::V2_0),
    };

    Some(BaseScore {
        r#type: score_type,
        score,
        severity: Severity::from((score, score_type)),
    })
}

/// Extracts all CVSS scores from a CVE record and registers them with the given [`ScoreCreator`].
///
/// Parses vector strings from both CNA and ADP containers using `FromStr`, bypassing any
/// dependency on JSON `baseScore`/`baseSeverity` fields. The `ScoreCreator` computes the
/// actual score from parsed metrics via `calculated_base_score()`.
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

    for metric in all_metrics {
        for cvss in parse_cvss_from_metric(metric) {
            creator.add((vulnerability_id.clone(), cvss));
        }
    }
}

/// Extracts the best base score from a CVE record by parsing vector strings.
///
/// Prefers CNA scores over ADP scores, only falling back to ADP if CNA yields no parseable
/// scores. Within each source, higher CVSS versions take precedence; within the same version,
/// the higher numeric score wins.
pub fn extract_base_score(cve: &Cve) -> Option<BaseScore> {
    fn better_score(a: BaseScore, b: BaseScore) -> BaseScore {
        if b.r#type > a.r#type || (b.r#type == a.r#type && b.score > a.score) {
            b
        } else {
            a
        }
    }

    let Cve::Published(published) = cve else {
        return None;
    };

    let cna_result = published
        .containers
        .cna
        .metrics
        .iter()
        .flat_map(parse_cvss_from_metric)
        .filter_map(|c| base_score_from_cvss(&c))
        .reduce(better_score);

    cna_result.or_else(|| {
        published
            .containers
            .adp
            .iter()
            .flat_map(|adp| adp.metrics.iter())
            .flat_map(parse_cvss_from_metric)
            .filter_map(|c| base_score_from_cvss(&c))
            .reduce(better_score)
    })
}
