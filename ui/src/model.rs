use serde::Deserialize;

pub use trustify_api::correlation::{
    AdvisoryStatement, ComponentRef, CorrelationOption, CorrelationOptionData,
    CorrelationOptionKey, CorrelationResult, EvidenceDetail, EvidenceRemediation, IdentifierKind,
    IdentifierRef, MatchedRange, MatchedValue, ProviderMatch, QueryResult, RangeBound,
    RemediationCategory, SbomVerdictCounts, StatementKind, StatementSubject, VerdictCountsRequest,
    VerdictStatus, VerdictSummary,
};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WellKnownInfo {
    pub frontend: trustify_api::FrontendInfo,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl WellKnownInfo {
    pub fn correlation_enabled(&self) -> bool {
        self.capabilities.iter().any(|name| name == "correlation")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResults<T> {
    pub items: Vec<T>,
    pub total: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SbomSummary {
    pub id: String,
    pub name: String,
    pub document_id: Option<String>,
    pub published: Option<String>,
    pub number_of_packages: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct IngestResult {
    pub id: String,
    pub document_id: Option<String>,
    #[serde(default)]
    pub duplicate: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// The response of creating a resource.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Created {
    pub id: uuid::Uuid,
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn discovery_requires_an_explicit_correlation_capability() {
        for (capabilities, enabled) in [
            (None, false),
            (Some(json!([])), false),
            (Some(json!(["recommendations"])), false),
            (Some(json!(["correlation", "futureCapability"])), true),
        ] {
            let mut discovery = json!({"frontend": {"oidc": null}});
            if let Some(capabilities) = capabilities {
                discovery["capabilities"] = capabilities;
            }
            let info: WellKnownInfo = serde_json::from_value(discovery).unwrap();
            assert_eq!(info.correlation_enabled(), enabled);
        }
    }
}
