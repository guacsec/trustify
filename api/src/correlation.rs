use serde::{Deserialize, Serialize};
use std::fmt;
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

/// A component and the identifiers attached to it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ComponentRef {
    pub node_id: String,
    pub name: String,
    pub identifiers: Vec<IdentifierRef>,
}

/// The kind of an identifier used for correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    Digest,
    Purl,
    Cpe,
    ModelNumber,
    SerialNumber,
    Sku,
}

impl IdentifierKind {
    /// All identifier kinds.
    pub const ALL: [Self; 6] = [
        Self::Digest,
        Self::Purl,
        Self::Cpe,
        Self::ModelNumber,
        Self::SerialNumber,
        Self::Sku,
    ];

    /// Serialized name, as used in the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Purl => "purl",
            Self::Cpe => "cpe",
            Self::ModelNumber => "model_number",
            Self::SerialNumber => "serial_number",
            Self::Sku => "sku",
        }
    }

    /// Human readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Digest => "Digest",
            Self::Purl => "PURL",
            Self::Cpe => "CPE",
            Self::ModelNumber => "Model Number",
            Self::SerialNumber => "Serial Number",
            Self::Sku => "SKU",
        }
    }
}

impl fmt::Display for IdentifierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// An identifier of a specific kind.
///
/// Digests use the format `<algorithm>:<value>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentifierRef {
    pub kind: IdentifierKind,
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
    pub assertion_status: AssertionStatus,
    pub confidence: f64,
    pub extractor: String,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_value: Option<String>,
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
    /// The identifier which was queried.
    pub query: IdentifierRef,
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
    pub kind: IdentifierKind,
    pub value: String,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
    pub status: AssertionStatus,
}

#[cfg(feature = "entity")]
mod entity_conversions {
    use super::*;
    use trustify_entity::{
        advisory_vulnerability_product_identifier::ProductIdentifierType as EntityProductIdentifierType,
        correlation_evidence::AssertionStatus as EntityAssertionStatus,
    };

    impl From<EntityProductIdentifierType> for IdentifierKind {
        fn from(value: EntityProductIdentifierType) -> Self {
            match value {
                EntityProductIdentifierType::ModelNumber => Self::ModelNumber,
                EntityProductIdentifierType::SerialNumber => Self::SerialNumber,
                EntityProductIdentifierType::Sku => Self::Sku,
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
}
