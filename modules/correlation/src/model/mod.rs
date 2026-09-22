use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_entity::correlation_evidence::{AssertionStatus, MatchDimension};
use utoipa::ToSchema;
use uuid::Uuid;

/// Top-level correlation result for an SBOM.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CorrelationResult {
    pub sbom_id: Uuid,
    pub verdicts: Vec<VerdictSummary>,
}

/// Resolved determination per (component, vulnerability) pair.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct VerdictSummary {
    pub component: ComponentRef,
    pub vulnerability: VulnerabilityRef,
    pub status: VerdictStatus,
    pub evidence: Vec<EvidenceDetail>,
}

/// Resolved verdict status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    None,
}

/// A component may have multiple PURLs, CPEs, and digests.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ComponentRef {
    pub node_id: String,
    pub name: String,
    pub purls: Vec<String>,
    pub cpes: Vec<String>,
    pub digests: Vec<DigestRef>,
}

/// A checksum on a component.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct DigestRef {
    pub algorithm: String,
    pub value: String,
}

/// Reference to an advisory's vulnerability assertion.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct VulnerabilityRef {
    pub id: String,
    pub title: Option<String>,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
}

/// One piece of evidence from the correlation_evidence table.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct EvidenceDetail {
    pub id: Uuid,
    pub match_dimension: MatchDimension,
    pub assertion_status: AssertionStatus,
    pub confidence: f64,
    pub extractor: String,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
