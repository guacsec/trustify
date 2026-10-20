//! Completion metadata is independent of evidence: zero matches can be current.
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Current,
    Stale,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExtractionFreshness {
    pub status: FreshnessStatus,
    pub required_revision: i64,
    pub completed_revision: Option<i64>,
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FreshnessOverview {
    pub revision: i64,
    pub checked_at: OffsetDateTime,
    pub total: u64,
    pub current: u64,
    pub stale: u64,
    pub unknown: u64,
    pub needs_refresh: u64,
    pub active_job: Option<RefreshJob>,
    pub latest_job: Option<RefreshJob>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FreshnessDocument {
    pub sbom_id: Uuid,
    pub name: String,
    pub freshness: ExtractionFreshness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RefreshJobStatus {
    Queued,
    Running,
    Completed,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RefreshJob {
    pub id: Uuid,
    pub revision: i64,
    pub status: RefreshJobStatus,
    /// Successfully processed documents. Failures are counted separately.
    pub processed: u64,
    pub failed: u64,
    pub created_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RefreshFailure {
    pub sbom_id: Uuid,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RefreshJobDetails {
    pub job: RefreshJob,
    pub failures: Vec<RefreshFailure>,
    pub failure_total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_responses_are_unknown_rather_than_current() {
        let id = Uuid::nil();
        let result: crate::correlation::CorrelationResult =
            serde_json::from_value(serde_json::json!({
                "sbom_id": id, "verdicts": []
            }))
            .unwrap();
        assert_eq!(result.freshness.status, FreshnessStatus::Unknown);
        let counts: crate::correlation::SbomVerdictCounts =
            serde_json::from_value(serde_json::json!({
                "sbom_id": id, "affected": 0, "fixed": 0, "not_affected": 0,
                "under_investigation": 0, "none": 0
            }))
            .unwrap();
        assert_eq!(counts.freshness.status, FreshnessStatus::Unknown);
    }

    #[test]
    fn freshness_uses_stable_api_status_names() {
        for (status, name) in [
            (FreshnessStatus::Current, "current"),
            (FreshnessStatus::Stale, "stale"),
            (FreshnessStatus::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), name);
            assert_eq!(
                serde_json::from_value::<FreshnessStatus>(serde_json::json!(name)).unwrap(),
                status
            );
        }
    }
}
