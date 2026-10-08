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
    pub matched_value: Option<MatchedValue>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// The advisory side of a match: what an SBOM identifier was matched against.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MatchedValue {
    /// The advisory identifier which matched, e.g. a PURL without a version, a CPE pattern, or a
    /// digest.
    pub identifier: String,
    /// The version ranges of the assertion which contain the SBOM version.
    ///
    /// Empty when no version range was involved in the match.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<MatchedRange>,
}

impl MatchedValue {
    /// A matched value without version ranges.
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ranges: Vec::new(),
        }
    }
}

impl fmt::Display for MatchedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.identifier)?;
        for (i, range) in self.ranges.iter().enumerate() {
            f.write_str(if i == 0 { " " } else { "; " })?;
            write!(f, "{range}")?;
        }
        Ok(())
    }
}

/// A version range of an advisory assertion. A missing bound is unbounded.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MatchedRange {
    /// The version scheme, e.g. `rpm` or `semver`.
    pub scheme: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low: Option<RangeBound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high: Option<RangeBound>,
}

/// Formats the range for humans, e.g. `rpm: < 1.2.3`, `semver: >= 1.0.0, < 2.0.0` or `semver: = 1.0.0`.
impl fmt::Display for MatchedRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.scheme)?;
        match (&self.low, &self.high) {
            (Some(low), Some(high)) if low == high && low.inclusive => {
                write!(f, "= {}", low.version)
            }
            (Some(low), Some(high)) => write!(f, "{}, {}", low.as_low(), high.as_high()),
            (Some(low), None) => write!(f, "{}", low.as_low()),
            (None, Some(high)) => write!(f, "{}", high.as_high()),
            (None, None) => f.write_str("any version"),
        }
    }
}

/// One bound of a [`MatchedRange`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RangeBound {
    pub version: String,
    pub inclusive: bool,
}

impl RangeBound {
    fn as_low(&self) -> String {
        let op = if self.inclusive { ">=" } else { ">" };
        format!("{op} {}", self.version)
    }

    fn as_high(&self) -> String {
        let op = if self.inclusive { "<=" } else { "<" };
        format!("{op} {}", self.version)
    }
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
    pub value: MatchedValue,
    pub advisory_id: Uuid,
    pub advisory_identifier: String,
    pub status: AssertionStatus,
    /// The type of evidence, i.e. how the match was established (e.g. `purl` or `purl_stream`).
    pub extractor: String,
    pub confidence: f64,
}

#[cfg(feature = "entity")]
mod entity_conversions {
    use super::*;
    use trustify_entity::{
        advisory_vulnerability_product_identifier::ProductIdentifierType as EntityProductIdentifierType,
        correlation_evidence::AssertionStatus as EntityAssertionStatus, version_range,
    };

    impl From<version_range::Model> for MatchedRange {
        fn from(value: version_range::Model) -> Self {
            let bound = |version: Option<String>, inclusive: Option<bool>| {
                version.map(|version| RangeBound {
                    version,
                    inclusive: inclusive.unwrap_or_default(),
                })
            };
            Self {
                scheme: value.version_scheme_id.to_string(),
                low: bound(value.low_version, value.low_inclusive),
                high: bound(value.high_version, value.high_inclusive),
            }
        }
    }

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

/// Request for the verdict counts of several SBOMs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerdictCountsRequest {
    /// The SBOMs to summarize.
    pub sbom_ids: Vec<Uuid>,
}

/// The number of verdicts, per (component, vulnerability), of an SBOM by status.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SbomVerdictCounts {
    pub sbom_id: Uuid,
    pub affected: u64,
    pub fixed: u64,
    pub not_affected: u64,
    pub under_investigation: u64,
    pub none: u64,
}

#[cfg(test)]
mod test {
    use super::*;

    fn bound(version: &str, inclusive: bool) -> Option<RangeBound> {
        Some(RangeBound {
            version: version.into(),
            inclusive,
        })
    }

    #[test]
    fn display_matched_value() {
        let range = |low, high| MatchedRange {
            scheme: "rpm".into(),
            low,
            high,
        };
        let value = MatchedValue {
            identifier: "pkg:rpm/redhat/bind".into(),
            ranges: vec![
                range(None, bound("1:2-3", false)),
                range(bound("1.0", true), bound("2.0", false)),
                range(bound("1.0", false), None),
                range(bound("1.0", true), bound("1.0", true)),
                range(None, None),
            ],
        };
        assert_eq!(
            value.to_string(),
            "pkg:rpm/redhat/bind rpm: < 1:2-3; rpm: >= 1.0, < 2.0; rpm: > 1.0; rpm: = 1.0; rpm: any version"
        );
    }
}
