//! Shared identity, assertion, evidence, and verdict data types.

use crate::version::{VersionRange, VersionScheme};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// A reference to the advisory that made an assertion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdvisoryRef {
    pub identifier: String,
    pub source_file: Option<String>,
}

/// VEX status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionStatus {
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    Recommended,
}

impl AssertionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::Fixed => "fixed",
            Self::NotAffected => "not_affected",
            Self::UnderInvestigation => "under_investigation",
            Self::Recommended => "recommended",
        }
    }

    /// Whether this status resolves (suppresses) an `Affected` assertion.
    pub fn resolves_affected(&self) -> bool {
        matches!(self, Self::Fixed | Self::NotAffected)
    }
}

/// Compatibility name for assertion statuses. Verdicts use `VerdictStatus` and
/// therefore cannot accidentally represent `recommended` as a verdict.
pub type Status = AssertionStatus;

/// Status of a resolved component/vulnerability verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    None,
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
}

impl VerdictStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Affected => "affected",
            Self::Fixed => "fixed",
            Self::NotAffected => "not_affected",
            Self::UnderInvestigation => "under_investigation",
        }
    }

    pub fn resolves_affected(&self) -> bool {
        matches!(self, Self::Fixed | Self::NotAffected)
    }
}

/// Identifier for a component being queried.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComponentId {
    Purl {
        ty: String,
        namespace: Option<String>,
        name: String,
        version: Option<String>,
        qualifiers: BTreeMap<String, String>,
    },
    Cpe(String),
    Hash {
        algorithm: String,
        value: String,
    },
}

impl ComponentId {
    pub fn purl_base_key(&self) -> Option<(&str, Option<&str>, &str)> {
        match self {
            Self::Purl {
                ty,
                namespace,
                name,
                ..
            } => Some((ty.as_str(), namespace.as_deref(), name.as_str())),
            _ => None,
        }
    }

    pub fn purl_version(&self) -> Option<&str> {
        match self {
            Self::Purl { version, .. } => version.as_deref(),
            _ => None,
        }
    }

    pub fn purl_type(&self) -> Option<&str> {
        match self {
            Self::Purl { ty, .. } => Some(ty.as_str()),
            _ => None,
        }
    }
}

/// Parse a Package URL string into a `ComponentId::Purl`.
pub fn parse_purl(purl_str: &str) -> Option<ComponentId> {
    let s = purl_str.strip_prefix("pkg:")?;

    let (s, _subpath) = s.split_once('#').map_or((s, None), |(s, sp)| (s, Some(sp)));
    let (s, qualifiers_str) = s.split_once('?').map_or((s, None), |(s, q)| (s, Some(q)));
    let (s, version) = s
        .split_once('@')
        .map_or((s, None), |(s, v)| (s, Some(percent_decode(v))));

    let (ty, rest) = s.split_once('/')?;
    let (namespace, name) = match rest.rsplit_once('/') {
        Some((ns, n)) => (Some(percent_decode(ns)), percent_decode(n)),
        None => (None, percent_decode(rest)),
    };

    let qualifiers = qualifiers_str
        .map(|q| {
            q.split('&')
                .filter_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    Some((percent_decode(k).to_ascii_lowercase(), percent_decode(v)))
                })
                .collect()
        })
        .unwrap_or_default();

    Some(ComponentId::Purl {
        ty: ty.to_lowercase(),
        namespace,
        name,
        version,
        qualifiers,
    })
}

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().and_then(hex_val);
            let lo = chars.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push(char::from(h << 4 | l));
            }
        } else {
            result.push(char::from(b));
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

/// A version range bundled with its comparison scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionConstraint {
    pub scheme: VersionScheme,
    pub range: VersionRange,
}

/// A single assertion from an advisory about a component's vulnerability status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionPolicy {
    /// A status without a version constraint applies to every version in its
    /// identity scope. This is the policy used for bare `known_affected`.
    AnyVersion,
    /// A versionless identity only applies to another versionless identity.
    IdentityOnly,
}

impl VersionPolicy {
    pub fn for_assertion(status: AssertionStatus, matcher: &ComponentMatcher) -> Self {
        if status == AssertionStatus::Affected
            && matches!(matcher, ComponentMatcher::Purl { version: None, .. })
        {
            Self::AnyVersion
        } else {
            Self::IdentityOnly
        }
    }
}

/// A single assertion from an advisory about a component's vulnerability status.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusAssertion {
    pub source: AdvisoryRef,
    pub vulnerability_id: String,
    pub status: AssertionStatus,
    pub matcher: ComponentMatcher,
    #[serde(default)]
    pub context: Vec<ContextRef>,
    #[serde(default)]
    pub grouping: Vec<GroupRef>,
    pub version_policy: VersionPolicy,
}

impl StatusAssertion {
    pub fn new(
        source: AdvisoryRef,
        vulnerability_id: String,
        status: AssertionStatus,
        matcher: ComponentMatcher,
    ) -> Self {
        Self {
            version_policy: VersionPolicy::for_assertion(status, &matcher),
            source,
            vulnerability_id,
            status,
            matcher,
            context: Vec::new(),
            grouping: Vec::new(),
        }
    }
}

/// How a status assertion identifies matching components.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComponentMatcher {
    Purl {
        ty: String,
        namespace: Option<String>,
        name: String,
        /// Qualifiers supplied by the advisory. An empty map matches any
        /// component qualifiers; present qualifiers must match exactly.
        qualifiers: BTreeMap<String, String>,
        version: Option<VersionConstraint>,
    },
    CpeMatch {
        cpe: String,
        version: Option<VersionConstraint>,
    },
    Hash {
        algorithm: String,
        value: String,
    },
    /// CVE 5.x product/vendor name — matched heuristically against SBOM components.
    CveProduct {
        product: String,
        version: VersionConstraint,
    },
}

/// The kind of product or platform context describing a component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    Product,
    OperatingSystem,
    Image,
    Other,
}

/// A context identity, such as a describing product CPE or operating system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContextRef {
    pub id: ComponentId,
    pub kind: ContextKind,
}

/// A relationship that groups a component with a containing or describing identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupingRelation {
    Contains,
    DependsOn,
    Describes,
    Other,
}

/// A typed edge between two identities. Grouping is never inferred from names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupRef {
    pub subject: ComponentId,
    pub target: ComponentId,
    pub relationship: GroupingRelation,
}

/// The resolved verdict for a single vulnerability against a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub component: ComponentId,
    #[serde(default)]
    pub context: Vec<ContextRef>,
    pub vulnerability_id: String,
    pub status: VerdictStatus,
    pub contributing_assertions: Vec<AssertionRef>,
    pub evidence: Vec<MatchEvidence>,
    pub resolution_rule: ResolutionRule,
    pub confidence: crate::confidence::Confidence,
}

/// A lightweight reference to an assertion that contributed to a verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionRef {
    pub source: AdvisoryRef,
    pub status: AssertionStatus,
    pub matched_by: MatchDimension,
    pub matcher: ComponentMatcher,
    pub version_constraint: Option<VersionConstraint>,
    pub version_in_range: Option<bool>,
    #[serde(default)]
    pub context: Vec<ContextRef>,
}

/// Which matching dimension produced the match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchDimension {
    Purl,
    Cpe,
    Hash,
    Product,
}

/// Ordered strength of identity evidence used during resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchSpecificity {
    Product,
    Cpe,
    Purl,
    QualifiedPurl,
    Hash,
}

/// Evidence explaining why a specific assertion matched (or didn't).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEvidence {
    pub component: ComponentId,
    pub assertion_source: AdvisoryRef,
    pub vulnerability_id: String,
    pub status: AssertionStatus,
    pub dimension: MatchDimension,
    pub matcher: ComponentMatcher,
    pub version_in_range: Option<bool>,
    pub identity_precision: crate::confidence::IdentityPrecision,
    pub version_quality: crate::confidence::VersionMatchQuality,
    pub version_constraint: Option<VersionConstraint>,
    #[serde(default)]
    pub context: Vec<ContextRef>,
}

/// Structured explanation of how a verdict was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionRule {
    NoApplicableAssertion,
    CpeAffectedWins,
    SpecificResolution,
    AffectedOnly,
    UnderInvestigationOnly,
}

/// A single entry in the decision trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub message: String,
    pub detail: Option<String>,
}

/// An SBOM component extracted from a CycloneDX or SPDX document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    pub id: ComponentId,
    #[serde(default)]
    pub context: Vec<ContextRef>,
    #[serde(default)]
    pub grouping: Vec<GroupRef>,
}

/// Query for a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentQuery {
    pub id: ComponentId,
    #[serde(default)]
    pub context: Vec<ContextRef>,
    #[serde(default)]
    pub grouping: Vec<GroupRef>,
}

impl ComponentQuery {
    pub fn new(id: ComponentId) -> Self {
        Self {
            id,
            context: Vec::new(),
            grouping: Vec::new(),
        }
    }
}

/// A scenario definition loaded from `expected.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ScenarioExpected {
    pub advisories: Vec<String>,
    pub sboms: HashMap<String, SbomExpectation>,
}

/// Expected results for a single SBOM in a scenario.
#[derive(Debug, Clone, Deserialize)]
pub struct SbomExpectation {
    pub correct: HashMap<String, String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_purl_basic() {
        let id = parse_purl("pkg:rpm/redhat/openssl@1.1.1k-7.el8?arch=x86_64&epoch=1");
        match id {
            Some(ComponentId::Purl {
                ty,
                namespace,
                name,
                version,
                qualifiers,
            }) => {
                assert_eq!(ty, "rpm");
                assert_eq!(namespace.as_deref(), Some("redhat"));
                assert_eq!(name, "openssl");
                assert_eq!(version.as_deref(), Some("1.1.1k-7.el8"));
                assert_eq!(qualifiers.get("arch").map(String::as_str), Some("x86_64"));
                assert_eq!(qualifiers.get("epoch").map(String::as_str), Some("1"));
            }
            other => panic!("expected Purl, got {other:?}"),
        }
    }

    #[test]
    fn parse_purl_no_version() {
        let id = parse_purl("pkg:rpm/redhat/openssl");
        match id {
            Some(ComponentId::Purl {
                ty,
                namespace,
                name,
                version,
                ..
            }) => {
                assert_eq!(ty, "rpm");
                assert_eq!(namespace.as_deref(), Some("redhat"));
                assert_eq!(name, "openssl");
                assert!(version.is_none());
            }
            other => panic!("expected Purl, got {other:?}"),
        }
    }

    #[test]
    fn parse_purl_encoded_slashes() {
        // %2F is an encoded slash within a single segment — NOT a path separator
        let id = parse_purl("pkg:golang/github.com%2Fexample%2Fpkg@1.0.0");
        match id {
            Some(ComponentId::Purl {
                ty,
                namespace,
                name,
                version,
                ..
            }) => {
                assert_eq!(ty, "golang");
                assert!(namespace.is_none());
                assert_eq!(name, "github.com/example/pkg");
                assert_eq!(version.as_deref(), Some("1.0.0"));
            }
            other => panic!("expected Purl, got {other:?}"),
        }
    }

    #[test]
    fn parse_purl_golang_namespace() {
        // Real golang PURL with literal slash separators
        let id = parse_purl("pkg:golang/github.com/example/pkg@1.0.0");
        match id {
            Some(ComponentId::Purl {
                ty,
                namespace,
                name,
                version,
                ..
            }) => {
                assert_eq!(ty, "golang");
                assert_eq!(namespace.as_deref(), Some("github.com/example"));
                assert_eq!(name, "pkg");
                assert_eq!(version.as_deref(), Some("1.0.0"));
            }
            other => panic!("expected Purl, got {other:?}"),
        }
    }

    #[test]
    fn parse_purl_pypi() {
        let id = parse_purl("pkg:pypi/urllib3@1.26.17");
        match id {
            Some(ComponentId::Purl {
                ty, name, version, ..
            }) => {
                assert_eq!(ty, "pypi");
                assert_eq!(name, "urllib3");
                assert_eq!(version.as_deref(), Some("1.26.17"));
            }
            other => panic!("expected Purl, got {other:?}"),
        }
    }

    #[test]
    fn parse_purl_invalid() {
        assert!(parse_purl("not-a-purl").is_none());
        assert!(parse_purl("pkg:").is_none());
    }
}
