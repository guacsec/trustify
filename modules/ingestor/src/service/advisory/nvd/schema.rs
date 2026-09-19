//! Minimal serde model for the subset of the NVD CVE API 2.0 `cve` object we consume.
//!
//! The `fkie-cad/nvd-json-data-feeds` mirror stores each CVE as a bare `cve` object
//! (the value of `vulnerabilities[].cve` from the NVD API), so no response wrapper is
//! modeled here. Only the fields trustify actually maps are declared; everything else
//! is ignored.

use serde::Deserialize;

/// A per-year feed file as published in the mirror's release assets
/// (`CVE-<year>.json.xz`): a small envelope around the list of bare NVD `cve`
/// objects. Each item is kept as a raw JSON fragment so its original bytes can
/// be handed straight to the ingestor (which re-parses it as [`NvdCve`]).
#[derive(Debug, Deserialize)]
pub struct NvdYearFeed {
    #[serde(default)]
    pub cve_items: Vec<Box<serde_json::value::RawValue>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCve {
    pub id: String,
    #[serde(default)]
    pub source_identifier: Option<String>,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub vuln_status: Option<String>,
    #[serde(default)]
    pub descriptions: Vec<LangString>,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub weaknesses: Vec<Weakness>,
    #[serde(default)]
    pub configurations: Vec<Configuration>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LangString {
    pub lang: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    #[serde(default)]
    pub cvss_metric_v40: Vec<CvssMetric>,
    #[serde(default)]
    pub cvss_metric_v31: Vec<CvssMetric>,
    #[serde(default)]
    pub cvss_metric_v30: Vec<CvssMetric>,
    #[serde(default)]
    pub cvss_metric_v2: Vec<CvssMetric>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetric {
    pub cvss_data: CvssData,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
    #[serde(default)]
    pub version: String,
    /// The canonical CVSS vector string (e.g. `CVSS:3.1/AV:N/...`). This is the
    /// authoritative source we re-parse; the numeric `baseScore` is recomputed.
    pub vector_string: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Weakness {
    #[serde(default)]
    pub description: Vec<LangString>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    #[serde(default)]
    pub nodes: Vec<Node>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    #[serde(default)]
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(default)]
    pub version_start_including: Option<String>,
    #[serde(default)]
    pub version_start_excluding: Option<String>,
    #[serde(default)]
    pub version_end_including: Option<String>,
    #[serde(default)]
    pub version_end_excluding: Option<String>,
}
