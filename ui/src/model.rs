use serde::Deserialize;

pub use trustify_api::correlation::{
    ComponentRef, CorrelationResult, EvidenceDetail, IdentifierKind, IdentifierRef, MatchedValue,
    QueryResult, SbomVerdictCounts, VerdictCountsRequest, VerdictStatus, VerdictSummary,
};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WellKnownInfo {
    pub frontend: trustify_api::FrontendInfo,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResults<T> {
    pub items: Vec<T>,
    pub total: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SbomSummary {
    pub id: String,
    pub name: String,
    pub document_id: Option<String>,
    pub published: Option<String>,
    pub number_of_packages: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct IngestResult {
    pub id: String,
    pub document_id: Option<String>,
    #[serde(default)]
    pub duplicate: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}
