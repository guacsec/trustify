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

/// An importer, as listed by the importer API.
///
/// The configuration is kept as JSON: it is edited as such, and only a few common fields are
/// shown.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Importer {
    pub name: String,
    pub configuration: serde_json::Value,
    pub state: ImporterState,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_run: Option<time::OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_success: Option<time::OffsetDateTime>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub progress: ImporterProgress,
}

impl Importer {
    /// The type of the importer, the single key of its configuration.
    pub fn kind(&self) -> &str {
        self.configuration
            .as_object()
            .and_then(|config| config.keys().next())
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// A field of the type specific configuration.
    pub fn field(&self, name: &str) -> Option<&serde_json::Value> {
        self.configuration.as_object()?.values().next()?.get(name)
    }

    pub fn disabled(&self) -> bool {
        self.field("disabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or_default()
    }

    pub fn text(&self, name: &str) -> &str {
        self.field(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ImporterState {
    Waiting,
    Running,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImporterProgress {
    pub message: Option<String>,
    pub current: Option<u32>,
    pub total: Option<u32>,
    /// Progress in percent (0..=1)
    pub percent: Option<f64>,
    pub estimated_seconds_remaining: Option<i64>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub estimated_completion: Option<time::OffsetDateTime>,
}

impl ImporterProgress {
    /// The estimated remaining time, e.g. `3.2m`.
    pub fn remaining(&self) -> Option<String> {
        self.estimated_seconds_remaining
            .map(|seconds| format!("{:.1}", time::Duration::seconds(seconds)))
    }
}

/// The report of an importer run.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ImporterReport {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub creation: time::OffsetDateTime,
    pub error: Option<String>,
    pub report: Option<RunReport>,
}

/// The details of an importer run.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunReport {
    #[serde(with = "time::serde::rfc3339")]
    pub start_date: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end_date: time::OffsetDateTime,
    #[serde(default)]
    pub number_of_items: u64,
    /// The messages by phase (e.g. `retrieval`), then by file.
    #[serde(default)]
    pub messages:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<RunMessage>>>,
}

impl RunReport {
    /// The messages as `(phase, file, message)`.
    pub fn messages(&self) -> impl Iterator<Item = (&str, &str, &RunMessage)> {
        self.messages.iter().flat_map(|(phase, files)| {
            files.iter().flat_map(move |(file, messages)| {
                messages
                    .iter()
                    .map(move |m| (phase.as_str(), file.as_str(), m))
            })
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RunMessage {
    /// `error` or `warning`
    pub severity: String,
    pub message: String,
}
