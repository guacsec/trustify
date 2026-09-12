//! Runtime policies controlling correlation behavior.

use serde::{Deserialize, Serialize};

/// Policy for assertions whose component has no version to compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionlessMatchPolicy {
    /// Do not apply version-constrained assertions to versionless components.
    Reject,
    /// Allow version-constrained assertions to apply without a component version.
    Allow,
}

/// Controls whether heuristic CVE product-name matches may contribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductMatchPolicy {
    /// Allow product-name matches to participate in resolution.
    Allow,
    /// Keep product-name matches as evidence but do not let them produce a definitive verdict.
    EvidenceOnly,
    /// Ignore product-name matches entirely.
    Reject,
}

/// Controls how conflicts between applicable assertions are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionPolicy {
    /// Preserve the conservative CPE-only affected behavior.
    Conservative,
    /// Always resolve using the strongest identity evidence first.
    SpecificityFirst,
}

/// Controls whether human-readable decision traces are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOptions {
    pub enabled: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Controls which vulnerabilities receive explicit `none` verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoneVerdictPolicy {
    /// Emit a verdict for every vulnerability present in the advisory evidence.
    AllKnown,
    /// Emit only for vulnerabilities with an identity match.
    IdentityMatched,
    /// Emit only for identifiers listed in `Evidence::requested_vulnerabilities`.
    ExplicitlyQueried,
}

/// Runtime options for correlation. Defaults preserve the current behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationOptions {
    pub versionless_matches: VersionlessMatchPolicy,
    pub product_matches: ProductMatchPolicy,
    pub resolution: ResolutionPolicy,
    pub none_verdicts: NoneVerdictPolicy,
    pub trace: TraceOptions,
}

impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            versionless_matches: VersionlessMatchPolicy::Reject,
            product_matches: ProductMatchPolicy::Allow,
            resolution: ResolutionPolicy::Conservative,
            none_verdicts: NoneVerdictPolicy::AllKnown,
            trace: TraceOptions::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CorrelationOptions, NoneVerdictPolicy, VersionlessMatchPolicy};

    #[test]
    fn defaults_preserve_safe_versionless_behavior() {
        assert_eq!(
            CorrelationOptions::default().versionless_matches,
            VersionlessMatchPolicy::Reject
        );
    }

    #[test]
    fn options_serialize_stably() {
        let options = CorrelationOptions {
            versionless_matches: VersionlessMatchPolicy::Allow,
            none_verdicts: NoneVerdictPolicy::ExplicitlyQueried,
            ..CorrelationOptions::default()
        };

        let json = serde_json::to_string(&options).expect("options should serialize");
        assert!(json.contains("\"versionless_matches\":\"allow\""));
        assert!(json.contains("\"none_verdicts\":\"explicitly_queried\""));
    }
}
