use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Top-level correlation result for an SBOM.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CorrelationResult {
    pub sbom_id: Uuid,
    pub verdicts: Vec<VerdictSummary>,
    /// Components in the SBOM that have no correlation evidence.
    ///
    /// `None` when not requested, `Some(vec)` when `include_unmatched=true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmatched_components: Option<Vec<ComponentRef>>,
}

/// Resolved determination per (component, vulnerability) pair.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerdictSummary {
    pub component: ComponentRef,
    pub vulnerability: VulnerabilityRef,
    pub status: VerdictStatus,
    pub evidence: Vec<EvidenceDetail>,
}

/// A component may have multiple PURLs, CPEs, and digests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ComponentRef {
    pub node_id: String,
    pub name: String,
    pub purls: Vec<String>,
    pub cpes: Vec<String>,
    pub digests: Vec<DigestRef>,
}

/// A checksum on a component.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DigestRef {
    pub algorithm: String,
    pub value: String,
}

/// Reference to an advisory's vulnerability assertion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VulnerabilityRef {
    pub id: String,
    pub title: Option<String>,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
}

/// One piece of evidence from the correlation engine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

/// Resolved verdict status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

/// Match dimension describing how a piece of evidence was correlated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

/// Status assertion from an advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

/// Result of a manual identifier query, grouped by vulnerability with resolved verdicts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct QueryResult {
    pub query: String,
    pub verdicts: Vec<QueryVerdict>,
}

/// Resolved verdict for a single vulnerability from an ad-hoc identifier query.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct QueryVerdict {
    pub vulnerability_id: String,
    pub vulnerability_title: Option<String>,
    pub status: VerdictStatus,
    pub matches: Vec<QueryMatch>,
}

/// A single match from the query (evidence within a verdict group).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct QueryMatch {
    pub match_type: QueryMatchType,
    pub value: String,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
    pub status: AssertionStatus,
}

/// The type of identifier that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum QueryMatchType {
    Digest,
    ModelNumber,
    SerialNumber,
    Sku,
}

impl QueryMatchType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Digest => "Digest",
            Self::ModelNumber => "Model Number",
            Self::SerialNumber => "Serial Number",
            Self::Sku => "SKU",
        }
    }
}

#[cfg(feature = "entity")]
mod entity_conversions {
    use super::*;
    use trustify_entity::{
        advisory_vulnerability_product_identifier::ProductIdentifierType,
        correlation_evidence::{
            AssertionStatus as EntityAssertionStatus, MatchDimension as EntityMatchDimension,
        },
    };

    impl From<ProductIdentifierType> for QueryMatchType {
        fn from(value: ProductIdentifierType) -> Self {
            match value {
                ProductIdentifierType::ModelNumber => Self::ModelNumber,
                ProductIdentifierType::SerialNumber => Self::SerialNumber,
                ProductIdentifierType::Sku => Self::Sku,
            }
        }
    }

    impl From<EntityAssertionStatus> for AssertionStatus {
        fn from(value: EntityAssertionStatus) -> Self {
            match value {
                EntityAssertionStatus::Affected => Self::Affected,
                EntityAssertionStatus::Fixed => Self::Fixed,
                EntityAssertionStatus::NotAffected => Self::NotAffected,
                EntityAssertionStatus::UnderInvestigation => Self::UnderInvestigation,
                EntityAssertionStatus::Recommended => Self::Recommended,
            }
        }
    }

    impl From<EntityMatchDimension> for MatchDimension {
        fn from(value: EntityMatchDimension) -> Self {
            match value {
                EntityMatchDimension::Digest => Self::Digest,
                EntityMatchDimension::Purl => Self::Purl,
                EntityMatchDimension::Cpe => Self::Cpe,
            }
        }
    }
}
