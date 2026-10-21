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

/// An exact identifier mapped to a canonical provider.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProviderAliasIdentifier {
    Name(String),
    Namespace(String),
    CveOrg(String),
    /// Package type and namespace, for example `rpm/acme`.
    Purl(String),
    Distro(String),
    CpeVendor(String),
}

impl ProviderAliasIdentifier {
    pub fn value(&self) -> &str {
        match self {
            Self::Name(v)
            | Self::Namespace(v)
            | Self::CveOrg(v)
            | Self::Purl(v)
            | Self::Distro(v)
            | Self::CpeVendor(v) => v,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Name(_) => "Name",
            Self::Namespace(_) => "Namespace",
            Self::CveOrg(_) => "CVE organization",
            Self::Purl(_) => "Package namespace",
            Self::Distro(_) => "Distribution",
            Self::CpeVendor(_) => "CPE vendor",
        }
    }

    /// Apply the same normalization as identifiers stated by ingested documents.
    pub fn normalized(&self) -> Self {
        let value = self.value().trim();
        match self {
            Self::Name(_) => Self::Name(
                value
                    .strip_prefix("Organization:")
                    .unwrap_or(value)
                    .trim()
                    .to_lowercase(),
            ),
            Self::Namespace(_) => Self::Namespace(value.trim_end_matches('/').into()),
            Self::CveOrg(_) => Self::CveOrg(value.trim_end_matches('/').into()),
            Self::Purl(_) => Self::Purl(value.trim_end_matches('/').into()),
            Self::Distro(_) => Self::Distro(value.trim_end_matches('/').into()),
            Self::CpeVendor(_) => Self::CpeVendor(value.trim_end_matches('/').into()),
        }
    }
}

/// Prefix encoding used by ingested identities, stored aliases, and text input.
impl std::fmt::Display for ProviderAliasIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Name(_) => "name",
            Self::Namespace(_) => "namespace",
            Self::CveOrg(_) => "cve-org",
            Self::Purl(_) => "purl",
            Self::Distro(_) => "distro",
            Self::CpeVendor(_) => "cpe-vendor",
        };
        write!(f, "{kind}:{}", self.value())
    }
}

impl std::str::FromStr for ProviderAliasIdentifier {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, value) = value.trim().split_once(':').ok_or("Expected kind:value")?;
        if value.trim().is_empty() {
            return Err("Alias value must not be empty");
        }
        Ok(match kind {
            "name" => Self::Name(value.into()),
            "namespace" => Self::Namespace(value.into()),
            "cve-org" => Self::CveOrg(value.into()),
            "purl" => Self::Purl(value.into()),
            "distro" => Self::Distro(value.into()),
            "cpe-vendor" => Self::CpeVendor(value.into()),
            _ => return Err("Unknown provider alias kind"),
        })
    }
}

/// An explicit mapping of supplier names, namespaces, or build identifiers to one provider.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderAliasData {
    pub provider: String,
    pub aliases: Vec<ProviderAliasIdentifier>,
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
    /// When true, include an explanation of how each verdict was resolved.
    #[serde(default)]
    pub include_explanation: bool,
    /// Only the verdicts of this SBOM node. Requires an SBOM target.
    pub node_id: Option<String>,
    /// Only the verdicts for this vulnerability, e.g. `CVE-2024-1234`.
    pub vulnerability_id: Option<String>,
    /// Temporary installed-build provider; does not change stored supplier metadata.
    pub component_provider: Option<String>,
    /// Identifiers of the product containing the component, e.g. its CPE, used to match
    /// product-scoped advisory statements. Only supported for identifier targets.
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

#[cfg(test)]
mod provider_alias_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identifiers_have_explicit_kinds_and_round_trip_storage_encoding() {
        for (kind, encoded, identifier) in [
            (
                "name",
                "name:Acme",
                ProviderAliasIdentifier::Name("Acme".into()),
            ),
            (
                "namespace",
                "namespace:https://acme.example",
                ProviderAliasIdentifier::Namespace("https://acme.example".into()),
            ),
            (
                "cve_org",
                "cve-org:example",
                ProviderAliasIdentifier::CveOrg("example".into()),
            ),
            (
                "purl",
                "purl:rpm/acme",
                ProviderAliasIdentifier::Purl("rpm/acme".into()),
            ),
            (
                "distro",
                "distro:acme",
                ProviderAliasIdentifier::Distro("acme".into()),
            ),
            (
                "cpe_vendor",
                "cpe-vendor:acme",
                ProviderAliasIdentifier::CpeVendor("acme".into()),
            ),
        ] {
            let value = json!({"kind": kind, "value": identifier.value()});
            assert_eq!(serde_json::to_value(&identifier).unwrap(), value);
            assert_eq!(
                serde_json::from_value::<ProviderAliasIdentifier>(value).unwrap(),
                identifier
            );
            assert_eq!(
                encoded.parse::<ProviderAliasIdentifier>().unwrap(),
                identifier
            );
            assert_eq!(identifier.to_string(), encoded);
        }
    }

    #[test]
    fn rejects_untyped_and_malformed_identifiers() {
        for value in [
            json!("name:Acme"),
            json!({"kind": "unknown", "value": "Acme"}),
            json!({"kind": "name"}),
            json!({"kind": "name", "value": 42}),
            json!({"kind": "name", "value": "Acme", "typo": true}),
        ] {
            assert!(serde_json::from_value::<ProviderAliasIdentifier>(value).is_err());
        }
        for encoded in ["Acme", "unknown:Acme", "name:", "name:  "] {
            assert!(encoded.parse::<ProviderAliasIdentifier>().is_err());
        }
    }

    #[test]
    fn normalization_preserves_identifier_kind() {
        assert_eq!(
            ProviderAliasIdentifier::Name(" Organization: ACME ".into()).normalized(),
            ProviderAliasIdentifier::Name("acme".into())
        );
        assert_eq!(
            ProviderAliasIdentifier::Namespace(" https://Acme.example/ ".into()).normalized(),
            ProviderAliasIdentifier::Namespace("https://Acme.example".into())
        );
        assert_ne!(
            ProviderAliasIdentifier::Name("acme".into()),
            ProviderAliasIdentifier::Distro("acme".into())
        );
    }
}
