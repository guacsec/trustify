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
pub enum Status {
    Affected,
    Fixed,
    NotAffected,
    UnderInvestigation,
    Recommended,
}

impl Status {
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

/// Identifier for a component being queried.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone)]
pub struct VersionConstraint {
    pub scheme: VersionScheme,
    pub range: VersionRange,
}

/// A single assertion from an advisory about a component's vulnerability status.
#[derive(Debug, Clone)]
pub struct StatusAssertion {
    pub source: AdvisoryRef,
    pub vulnerability_id: String,
    pub status: Status,
    pub matcher: ComponentMatcher,
}

/// How a status assertion identifies matching components.
#[derive(Debug, Clone)]
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
    /// CVE 5.x product/vendor name — matched heuristically against SBOM components.
    CveProduct {
        product: String,
        version: VersionConstraint,
    },
}

/// The resolved verdict for a single vulnerability against a single component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub vulnerability_id: String,
    pub status: Status,
    pub contributing_assertions: Vec<AssertionRef>,
}

/// A lightweight reference to an assertion that contributed to a verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionRef {
    pub source: AdvisoryRef,
    pub status: Status,
    pub matched_by: MatchDimension,
}

/// Which matching dimension produced the match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchDimension {
    Purl,
    Cpe,
}

/// Evidence explaining why a specific assertion matched (or didn't).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEvidence {
    pub assertion_source: AdvisoryRef,
    pub vulnerability_id: String,
    pub status: Status,
    pub dimension: MatchDimension,
    pub version_in_range: Option<bool>,
}

/// A single entry in the decision trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub message: String,
    pub detail: Option<String>,
}

/// An SBOM component extracted from a CycloneDX or SPDX document.
#[derive(Debug, Clone)]
pub struct SbomComponent {
    pub id: ComponentId,
}

/// The input for correlating an entire SBOM.
#[derive(Debug, Clone)]
pub struct SbomInput {
    pub name: String,
    pub components: Vec<SbomComponent>,
}

/// Query for a single component.
#[derive(Debug, Clone)]
pub struct ComponentQuery {
    pub id: ComponentId,
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
