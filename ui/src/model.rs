use serde::Deserialize;

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
pub struct CorrelationResult {
    pub sbom_id: String,
    pub verdicts: Vec<VerdictSummary>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct VerdictSummary {
    pub component: ComponentRef,
    pub vulnerability: VulnerabilityRef,
    pub status: VerdictStatus,
    pub evidence: Vec<EvidenceDetail>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    None,
}

impl VerdictStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Affected => "Affected",
            Self::Fixed => "Fixed",
            Self::NotAffected => "Not Affected",
            Self::UnderInvestigation => "Under Investigation",
            Self::None => "None",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ComponentRef {
    pub node_id: String,
    pub name: String,
    pub purls: Vec<String>,
    pub cpes: Vec<String>,
    pub digests: Vec<DigestRef>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DigestRef {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct VulnerabilityRef {
    pub id: String,
    pub title: Option<String>,
    pub advisory_id: String,
    pub advisory_identifier: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct EvidenceDetail {
    pub id: String,
    pub match_dimension: MatchDimension,
    pub assertion_status: AssertionStatus,
    pub confidence: f64,
    pub extractor: String,
    pub advisory_id: String,
    pub advisory_identifier: String,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchDimension {
    Digest,
    Purl,
    Cpe,
}

impl MatchDimension {
    pub fn label(self) -> &'static str {
        match self {
            Self::Digest => "Digest",
            Self::Purl => "PURL",
            Self::Cpe => "CPE",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssertionStatus {
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    Recommended,
}

impl AssertionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Affected => "Affected",
            Self::Fixed => "Fixed",
            Self::NotAffected => "Not Affected",
            Self::UnderInvestigation => "Under Investigation",
            Self::Recommended => "Recommended",
        }
    }
}
