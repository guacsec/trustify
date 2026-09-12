//! Confidence assessment derived from structured match evidence.

use serde::{Deserialize, Serialize};

use crate::types::MatchEvidence;

/// Degradation tier for a correlation confidence assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceTier {
    None,
    Exact,
    Strong,
    Coarse,
    Weak,
    NameOnly,
}

impl ConfidenceTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Exact => "exact",
            Self::Strong => "strong",
            Self::Coarse => "coarse",
            Self::Weak => "weak",
            Self::NameOnly => "name_only",
        }
    }
}

/// Precision of the identity evidence that produced a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPrecision {
    NameOnly,
    Cpe,
    BasePurl,
    QualifiedPurl,
    Digest,
}

/// Quality of the version comparison supporting a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionMatchQuality {
    NotChecked,
    Unbounded,
    Bounded,
    Exact,
}

impl IdentityPrecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::QualifiedPurl => "qualified_purl",
            Self::BasePurl => "base_purl",
            Self::Cpe => "cpe",
            Self::NameOnly => "name_only",
        }
    }
}

impl VersionMatchQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Bounded => "bounded",
            Self::Unbounded => "unbounded",
            Self::NotChecked => "not_checked",
        }
    }
}

/// Structured confidence and the factors used to calculate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confidence {
    pub tier: ConfidenceTier,
    pub score: u8,
    pub identity: IdentityPrecision,
    pub version: VersionMatchQuality,
    pub contradictory: bool,
    pub source_trust: Option<u8>,
    pub sbom_trust: Option<u8>,
}

impl Confidence {
    pub fn none() -> Self {
        Self {
            tier: ConfidenceTier::None,
            score: 0,
            identity: IdentityPrecision::NameOnly,
            version: VersionMatchQuality::NotChecked,
            contradictory: false,
            source_trust: None,
            sbom_trust: None,
        }
    }

    pub fn explanation(self) -> String {
        format!(
            "confidence={} ({}): identity={}, version={}, contradictory={}",
            self.tier.as_str(),
            self.score,
            self.identity.as_str(),
            self.version.as_str(),
            self.contradictory,
        )
    }
}

/// Compute confidence from applicable match evidence and contradiction state.
pub(crate) fn assess(evidence: &[MatchEvidence], contradictory: bool) -> Confidence {
    let applicable: Vec<_> = evidence
        .iter()
        .filter(|evidence| evidence.version_in_range == Some(true))
        .collect();
    let Some(strongest) = applicable
        .iter()
        .max_by_key(|evidence| identity_precision_score(evidence.identity_precision))
    else {
        return Confidence::none();
    };

    let version_score = if strongest.identity_precision == IdentityPrecision::Digest
        && strongest.version_quality == VersionMatchQuality::NotChecked
    {
        100
    } else {
        version_quality_score(strongest.version_quality)
    };
    let mut score = identity_precision_score(strongest.identity_precision).min(version_score);
    if contradictory {
        score = ((score as u16 * 4) / 5) as u8;
    }

    Confidence {
        tier: tier_for(score),
        score,
        identity: strongest.identity_precision,
        version: strongest.version_quality,
        contradictory,
        source_trust: None,
        sbom_trust: None,
    }
}

fn identity_precision_score(precision: IdentityPrecision) -> u8 {
    match precision {
        IdentityPrecision::Digest => 100,
        IdentityPrecision::QualifiedPurl => 90,
        IdentityPrecision::BasePurl => 80,
        IdentityPrecision::Cpe => 70,
        IdentityPrecision::NameOnly => 30,
    }
}

fn version_quality_score(quality: VersionMatchQuality) -> u8 {
    match quality {
        VersionMatchQuality::Exact => 100,
        VersionMatchQuality::Bounded => 95,
        VersionMatchQuality::Unbounded => 60,
        VersionMatchQuality::NotChecked => 40,
    }
}

fn tier_for(score: u8) -> ConfidenceTier {
    match score {
        95..=100 => ConfidenceTier::Exact,
        85..=94 => ConfidenceTier::Strong,
        70..=84 => ConfidenceTier::Coarse,
        40..=69 => ConfidenceTier::Weak,
        _ => ConfidenceTier::NameOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfidenceTier, IdentityPrecision, VersionMatchQuality, assess};
    use crate::types::{
        AdvisoryRef, AssertionStatus, ComponentId, ComponentMatcher, MatchDimension, MatchEvidence,
        VersionConstraint,
    };
    use crate::version::{VersionRange, VersionScheme};
    use std::collections::BTreeMap;

    fn evidence(identity: IdentityPrecision, version: VersionMatchQuality) -> MatchEvidence {
        MatchEvidence {
            component: ComponentId::Hash {
                algorithm: "sha256".into(),
                value: "abc".into(),
            },
            assertion_source: AdvisoryRef {
                identifier: "CVE-test".into(),
                source_file: None,
            },
            vulnerability_id: "CVE-test".into(),
            status: AssertionStatus::Affected,
            dimension: MatchDimension::Purl,
            matcher: ComponentMatcher::Purl {
                ty: "rpm".into(),
                namespace: None,
                name: "test".into(),
                qualifiers: BTreeMap::new(),
                version: Some(VersionConstraint {
                    scheme: VersionScheme::Rpm,
                    range: VersionRange::Exact("1".into()),
                }),
            },
            version_in_range: Some(true),
            identity_precision: identity,
            version_quality: version,
            version_constraint: None,
            context: Vec::new(),
        }
    }

    #[test]
    fn bounded_qualified_purl_is_strong() {
        let result = assess(
            &[evidence(
                IdentityPrecision::QualifiedPurl,
                VersionMatchQuality::Bounded,
            )],
            false,
        );
        assert_eq!(result.tier, ConfidenceTier::Strong);
        assert_eq!(result.score, 90);
    }

    #[test]
    fn contradiction_reduces_confidence() {
        let result = assess(
            &[evidence(
                IdentityPrecision::BasePurl,
                VersionMatchQuality::Bounded,
            )],
            true,
        );
        assert_eq!(result.tier, ConfidenceTier::Weak);
        assert_eq!(result.score, 64);
        assert!(result.contradictory);
    }

    #[test]
    fn no_applicable_evidence_is_none() {
        let mut item = evidence(IdentityPrecision::Digest, VersionMatchQuality::Exact);
        item.version_in_range = Some(false);
        let result = assess(&[item], false);
        assert_eq!(result.tier, ConfidenceTier::None);
        assert_eq!(result.score, 0);
    }
}
