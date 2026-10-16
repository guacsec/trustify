use super::{AssertionOrigin, AssertionStatus, IdentifierRef, VerdictStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PolicyScope {
    Instance,
    Group { group_id: Uuid },
    Sbom { sbom_id: Uuid },
    Component { sbom_id: Uuid, node_id: String },
}

/// A sparse override. Unset values inherit; entries in maps replace the same inherited key.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WeightOverrides {
    pub matching_provider: Option<f64>,
    /// Unverified match: both sides state the same provider name, but no alias maps it.
    pub matching_provider_name: Option<f64>,
    pub providerless: Option<f64>,
    pub providerless_fallback: Option<f64>,
    pub other_provider: Option<f64>,
    pub direct: Option<f64>,
    pub inferred: Option<f64>,
    pub conflict_sensitivity: Option<f64>,
    /// An explicit installed-build provider, not the author of the SBOM document.
    pub component_provider: Option<String>,
    #[serde(default)]
    pub providers: BTreeMap<String, f64>,
    /// Matching strategy IDs: digest, purl, cpe, product_identifier, or extension IDs.
    #[serde(default)]
    pub match_methods: BTreeMap<String, f64>,
    #[serde(default)]
    pub rules: BTreeMap<String, f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WeightPolicyData {
    pub scope: PolicyScope,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub weights: WeightOverrides,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WeightPolicy {
    pub id: Uuid,
    pub revision: Uuid,
    #[serde(flatten)]
    pub data: WeightPolicyData,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolutionSummary {
    pub decision_weight: f64,
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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SettingOrigin {
    pub source: String,
    pub policy_id: Option<Uuid>,
    pub revision: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<PolicyScope>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EffectiveSetting {
    pub value: serde_json::Value,
    pub origin: SettingOrigin,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AppliedWeight {
    pub factor: String,
    pub multiplier: f64,
    pub origin: SettingOrigin,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EvidenceWeight {
    pub evidence_ref: String,
    pub advisory_id: Uuid,
    pub status: AssertionStatus,
    pub match_confidence: f64,
    pub assertion_origin: AssertionOrigin,
    pub provider: ProviderResolution,
    pub factors: Vec<AppliedWeight>,
    pub weight: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StatusWeight {
    pub status: VerdictStatus,
    pub weight: f64,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolutionExplanation {
    pub component_provider: ProviderResolution,
    /// Revision of the complete effective policy, including provider aliases.
    pub policy_revision: Uuid,
    pub settings: BTreeMap<String, EffectiveSetting>,
    pub evidence: Vec<EvidenceWeight>,
    pub statuses: Vec<StatusWeight>,
    pub winning_evidence: Option<String>,
    pub opposing_evidence: Option<String>,
    pub opposing_weight: f64,
    pub base_confidence: f64,
    pub confidence_penalty: f64,
    pub tie_break: bool,
    pub reason: String,
}

/// Optional resolution context, shared by ordinary reads and temporary previews.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolutionRequest {
    #[serde(default)]
    pub include_explanation: bool,
    pub node_id: Option<String>,
    pub vulnerability_id: Option<String>,
    pub group_id: Option<Uuid>,
    #[serde(default)]
    pub overrides: WeightOverrides,
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
