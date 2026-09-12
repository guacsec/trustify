//! Normalized advisory and SBOM facts supplied to correlation.

use serde::{Deserialize, Serialize};

/// Normalized advisory facts extracted from an advisory document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvisoryEvidence {
    pub assertions: Vec<StatusAssertion>,
}

/// Normalized SBOM facts extracted from an SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomEvidence {
    pub name: String,
    pub components: Vec<SbomComponent>,
    pub context: Vec<ContextRef>,
    pub grouping: Vec<GroupRef>,
}

/// Complete correlation input: advisory evidence joined with SBOM evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub advisory: AdvisoryEvidence,
    pub sbom: SbomEvidence,
    /// Optional vulnerability scope for `NoneVerdictPolicy::ExplicitlyQueried`.
    #[serde(default)]
    pub requested_vulnerabilities: Vec<String>,
}

impl Evidence {
    pub fn new(advisory: AdvisoryEvidence, sbom: SbomEvidence) -> Self {
        Self {
            advisory,
            sbom,
            requested_vulnerabilities: Vec::new(),
        }
    }
}

pub use crate::types::{
    AssertionRef, AssertionStatus, ComponentMatcher, ComponentQuery, ContextRef, GroupRef,
    MatchDimension, MatchEvidence, SbomComponent, StatusAssertion, VersionConstraint,
    VersionPolicy,
};
