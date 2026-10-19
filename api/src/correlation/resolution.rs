use super::{
    AssertionOrigin, AssertionStatus, ConfidenceFactor, EvidenceContext, EvidenceRemediation,
    IdentifierRef, VerdictStatus,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How the provider of an assertion matches the provider of the SBOM component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProviderMatch {
    /// Both resolve to the same provider.
    Provider,
    /// Both state the same provider name, and they do not resolve to different providers.
    Name,
}

/// Identifiers claimed by a supplier or assertion source, before applying provider aliases.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderIdentity {
    #[serde(default)]
    pub identifiers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// True when the source predates provider attribution and cannot be recovered safely.
    #[serde(default)]
    pub unavailable: bool,
}

/// An explicit mapping of supplier names, namespaces, or build identifiers to one provider.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderAliasData {
    pub provider: String,
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderAlias {
    pub id: Uuid,
    pub revision: Uuid,
    #[serde(flatten)]
    pub data: ProviderAliasData,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolutionSummary {
    /// Original match confidence of the selected evidence; conflicts do not reduce it.
    pub confidence: f64,
    pub has_conflict: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<ResolutionExplanation>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderResolution {
    pub provider: Option<String>,
    pub source: String,
    pub identifiers: Vec<String>,
    pub diagnostics: Vec<String>,
}

/// Provider precedence, ordered from most to least preferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProviderRelationship {
    MatchingProvider,
    MatchingName,
    Providerless,
    Other,
}

impl ProviderRelationship {
    pub fn label(self) -> &'static str {
        match self {
            Self::MatchingProvider => "Same provider",
            Self::MatchingName => "Same name (unverified)",
            Self::Providerless => "Providerless",
            Self::Other => "Other or unresolved provider",
        }
    }
}

/// First criterion that distinguishes the selected statement from another statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    NoEligibleEvidence,
    OnlyEligibleEvidence,
    ProviderRelationship,
    AssertionOrigin,
    MatchConfidence,
    StatusPriority,
    EvidenceReference,
    NonVoting,
}

impl SelectionReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::NoEligibleEvidence => "No eligible statement selects a verdict.",
            Self::OnlyEligibleEvidence => "This is the only eligible statement.",
            Self::ProviderRelationship => {
                "The selected statement has the preferred provider relationship."
            }
            Self::AssertionOrigin => {
                "The selected statement is direct or an explicit default; the other statement is inferred or has unknown origin."
            }
            Self::MatchConfidence => "The selected statement has higher original match confidence.",
            Self::StatusPriority => {
                "Provider relationship, directness and confidence are equal; status priority selects affected, fixed, not affected, then under investigation."
            }
            Self::EvidenceReference => {
                "Equivalent statements are ordered by their stable evidence reference."
            }
            Self::NonVoting => {
                "Recommended and zero-confidence statements do not select a verdict."
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Selected,
    Supporting,
    Conflicting,
    NonVoting,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolutionEvidence {
    pub evidence_ref: String,
    pub advisory_id: Uuid,
    pub status: AssertionStatus,
    pub match_confidence: f64,
    pub assertion_origin: AssertionOrigin,
    pub provider: ProviderResolution,
    pub provider_relationship: ProviderRelationship,
    pub outcome: EvidenceOutcome,
    pub selection_reason: SelectionReason,
    /// The products (assertion contexts) the statement was matched in, and how the component got
    /// into them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contexts: Vec<EvidenceContext>,
    /// The factors of the match confidence, empty for evidence extracted before they were
    /// recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_factors: Vec<ConfidenceFactor>,
    /// The remediations the advisory states for the statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remediations: Vec<EvidenceRemediation>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolutionExplanation {
    pub status: VerdictStatus,
    pub component_provider: ProviderResolution,
    /// Fingerprint of resolver version, aliases, and resolution context.
    pub resolution_revision: Uuid,
    /// Ordered by eligibility, then the fixed resolution precedence.
    pub evidence: Vec<ResolutionEvidence>,
    pub winning_evidence: Option<String>,
    pub opposing_evidence: Option<String>,
    pub deciding_criterion: SelectionReason,
    pub reason: String,
}

/// Optional resolution context, shared by ordinary reads and temporary previews.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ResolutionRequest {
    #[serde(default)]
    pub include_explanation: bool,
    pub node_id: Option<String>,
    pub vulnerability_id: Option<String>,
    /// Temporary installed-build provider; does not change stored supplier metadata.
    pub component_provider: Option<String>,
    #[serde(default)]
    pub product_context: Vec<IdentifierRef>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PreviewTarget {
    Sbom { sbom_id: Uuid },
    Identifier { identifier: IdentifierRef },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub target: PreviewTarget,
    #[serde(default)]
    pub resolution: ResolutionRequest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
pub enum PreviewResult {
    Sbom(super::CorrelationResult),
    Identifier(super::QueryResult),
}
