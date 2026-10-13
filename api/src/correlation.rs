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
    /// The products (assertion contexts) the evidence was matched in. Empty when the assertion
    /// has no context, or the SBOM nothing to compare it with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contexts: Vec<EvidenceContext>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A product (assertion context) a piece of evidence was matched in, and how the SBOM component
/// got into it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EvidenceContext {
    pub context_id: Uuid,
    /// The name of the product, e.g. "Red Hat Storage 3".
    pub name: String,
    /// How the subject of the assertion relates to the product, if stated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<ContextCategory>,
    /// Where the component got the matching CPE from.
    pub source: ContextSource,
    /// Hops from the component (ancestor node) or SBOM (ancestor SBOM), 0 otherwise.
    pub distance: i32,
    /// The SBOM side CPE which matched.
    pub node_identifier: String,
    /// The product's CPE which matched.
    pub context_identifier: String,
    /// The confidence of this context, applied to the evidence.
    pub confidence: f64,
}

/// How the subject of an assertion relates to its context (CSAF relationship categories).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContextCategory {
    DefaultComponentOf,
    ExternalComponentOf,
    InstalledOn,
    InstalledWith,
    OptionalComponentOf,
}

/// Where an SBOM component got a CPE putting it into a product from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ContextSource {
    /// The component's own CPE.
    Node,
    /// The CPE of an ancestor component in the same SBOM.
    AncestorNode,
    /// A describing CPE of the SBOM.
    Describing,
    /// A describing CPE of an ancestor SBOM.
    AncestorSbom,
    /// The product of an RPM, by the `distro=` qualifier of its PURL.
    PurlQualifier,
    /// The product of an RPM, by the release of its version.
    PurlRelease,
}

impl ContextSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Node => "component",
            Self::AncestorNode => "ancestor component",
            Self::Describing => "SBOM",
            Self::AncestorSbom => "ancestor SBOM",
            Self::PurlQualifier => "distro qualifier",
            Self::PurlRelease => "release",
        }
    }
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
    /// The option which enabled the match, if it depends on one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_by: Option<EnabledBy>,
}

impl MatchedValue {
    /// A matched value without version ranges.
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ranges: Vec::new(),
            enabled_by: None,
        }
    }
}

/// The correlation option which enabled a match, as it was when the evidence was extracted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnabledBy {
    pub option_id: Uuid,
    pub key: CorrelationOptionKey,
    pub publisher_namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl fmt::Display for EnabledBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} for {}", self.key, self.publisher_namespace)?;
        if let Some(reason) = &self.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

/// The options of the correlation engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CorrelationOptionKey {
    /// A versionless PURL (e.g. `pkg:rpm/redhat/golang`) states the status of all versions of the
    /// package. The value is a boolean.
    VersionlessPurl,
    /// A `fixed` version means `first_fixed`: earlier versions of the stream are affected, later
    /// ones are fixed. The value is a boolean.
    FixedIsFirstFixed,
}

impl CorrelationOptionKey {
    /// All option keys.
    pub const ALL: [Self; 2] = [Self::VersionlessPurl, Self::FixedIsFirstFixed];

    /// The key, as serialized.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VersionlessPurl => "versionless_purl",
            Self::FixedIsFirstFixed => "fixed_is_first_fixed",
        }
    }
}

impl fmt::Display for CorrelationOptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An option of the correlation engine, for the advisories of one publisher.
///
/// A changed option applies to documents extracted afterwards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CorrelationOption {
    pub id: Uuid,
    #[serde(flatten)]
    pub data: CorrelationOptionData,
}

/// The settable content of a correlation option.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CorrelationOptionData {
    pub key: CorrelationOptionKey,
    /// The publisher namespace of the advisories the option applies to, e.g.
    /// `https://www.redhat.com`.
    pub publisher_namespace: String,
    /// The value, its type depends on the key.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub value: serde_json::Value,
    /// Why the option is set, shown with the evidence it enables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

/// The kind of subject an advisory statement is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    Purl,
    Cpe,
    Product,
}

impl StatementKind {
    /// All kinds.
    pub const ALL: [Self; 3] = [Self::Purl, Self::Cpe, Self::Product];

    /// The kind, as serialized.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Purl => "purl",
            Self::Cpe => "cpe",
            Self::Product => "product",
        }
    }
}

/// A status an advisory states for a vulnerability, as stored when the advisory was ingested.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AdvisoryStatement {
    pub vulnerability_id: String,
    /// The stated status (slug), e.g. `affected`, `fixed` or `first_fixed`.
    pub status: String,
    pub subject: StatementSubject,
    /// The versions the statement applies to. Unbounded when it applies to all versions.
    pub range: MatchedRange,
}

/// What an advisory statement is about.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatementSubject {
    /// A package, by its PURL without a version, e.g. `pkg:rpm/redhat/bind`.
    Purl { purl: String },
    /// A CPE, as CPE 2.3 formatted string.
    Cpe { cpe: String },
    /// A product, optionally narrowed to a package of it.
    Product {
        name: String,
        /// The CPE key of the product version, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cpe_key: Option<String>,
        /// The package of the product the statement is about, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package: Option<String>,
        /// The CSAF product IDs the statement originates from.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        csaf_product_ids: Vec<String>,
    },
}

#[cfg(feature = "entity")]
mod entity_conversions {
    use super::*;
    use trustify_entity::{
        advisory_vulnerability_product_identifier::ProductIdentifierType as EntityProductIdentifierType,
        assertion_context::AssertionContextCategory as EntityCategory,
        correlation_evidence::AssertionStatus as EntityAssertionStatus,
        correlation_evidence_context::ContextSource as EntityContextSource,
        correlation_option::{self, CorrelationOptionKey as EntityCorrelationOptionKey},
        version_range,
    };

    impl From<EntityCategory> for ContextCategory {
        fn from(value: EntityCategory) -> Self {
            match value {
                EntityCategory::DefaultComponentOf => Self::DefaultComponentOf,
                EntityCategory::ExternalComponentOf => Self::ExternalComponentOf,
                EntityCategory::InstalledOn => Self::InstalledOn,
                EntityCategory::InstalledWith => Self::InstalledWith,
                EntityCategory::OptionalComponentOf => Self::OptionalComponentOf,
            }
        }
    }

    impl From<EntityContextSource> for ContextSource {
        fn from(value: EntityContextSource) -> Self {
            match value {
                EntityContextSource::Node => Self::Node,
                EntityContextSource::AncestorNode => Self::AncestorNode,
                EntityContextSource::Describing => Self::Describing,
                EntityContextSource::AncestorSbom => Self::AncestorSbom,
                EntityContextSource::PurlQualifier => Self::PurlQualifier,
                EntityContextSource::PurlRelease => Self::PurlRelease,
            }
        }
    }

    impl From<EntityCorrelationOptionKey> for CorrelationOptionKey {
        fn from(value: EntityCorrelationOptionKey) -> Self {
            match value {
                EntityCorrelationOptionKey::VersionlessPurl => Self::VersionlessPurl,
                EntityCorrelationOptionKey::FixedIsFirstFixed => Self::FixedIsFirstFixed,
            }
        }
    }

    impl From<CorrelationOptionKey> for EntityCorrelationOptionKey {
        fn from(value: CorrelationOptionKey) -> Self {
            match value {
                CorrelationOptionKey::VersionlessPurl => Self::VersionlessPurl,
                CorrelationOptionKey::FixedIsFirstFixed => Self::FixedIsFirstFixed,
            }
        }
    }

    impl From<correlation_option::Model> for CorrelationOption {
        fn from(value: correlation_option::Model) -> Self {
            Self {
                id: value.id,
                data: CorrelationOptionData {
                    key: value.key.into(),
                    publisher_namespace: value.publisher_namespace,
                    value: value.value,
                    reason: value.reason,
                },
            }
        }
    }

    impl From<correlation_option::Model> for EnabledBy {
        fn from(value: correlation_option::Model) -> Self {
            Self {
                option_id: value.id,
                key: value.key.into(),
                publisher_namespace: value.publisher_namespace,
                reason: value.reason,
            }
        }
    }

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
            enabled_by: None,
        };
        assert_eq!(
            value.to_string(),
            "pkg:rpm/redhat/bind rpm: < 1:2-3; rpm: >= 1.0, < 2.0; rpm: > 1.0; rpm: = 1.0; rpm: any version"
        );
    }
}
