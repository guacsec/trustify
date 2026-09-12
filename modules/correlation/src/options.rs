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

/// Runtime options for the stateless correlation function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationOptions {
    pub versionless_matches: VersionlessMatchPolicy,
}

impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            versionless_matches: VersionlessMatchPolicy::Reject,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CorrelationOptions, VersionlessMatchPolicy};

    #[test]
    fn defaults_to_rejecting_versionless_matches() {
        assert_eq!(
            CorrelationOptions::default().versionless_matches,
            VersionlessMatchPolicy::Reject
        );
    }

    #[test]
    fn versionless_policy_serializes_stably() {
        let options = CorrelationOptions {
            versionless_matches: VersionlessMatchPolicy::Allow,
        };

        assert_eq!(
            serde_json::to_string(&options).expect("options should serialize"),
            r#"{"versionless_matches":"allow"}"#
        );
    }
}
