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
    /// Ingestion changes whose background extraction has not committed yet.
    /// Absent when talking to a server without durable extraction tracking.
    #[serde(default)]
    pub extraction_lag: Option<ExtractionLag>,
    /// Verdict work, including global invalidations not yet processed by a worker.
    #[serde(default)]
    pub verdict_lag: VerdictLag,
    pub active_job: Option<RefreshJob>,
    pub latest_job: Option<RefreshJob>,
}

/// Freshness of a published verdict snapshot, including upstream extraction lag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerdictFreshness {
    /// Unknown means no completed computation, not zero findings.
    pub status: FreshnessStatus,
    pub generation: Option<Uuid>,
    pub completed_at: Option<OffsetDateTime>,
    pub required_revision: i64,
    pub completed_revision: Option<i64>,
}

/// Durable outstanding verdict work. Failed work is a subset of pending work.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerdictLag {
    /// Includes work currently being processed and work implied by global invalidation.
    pub pending: u64,
    pub failed: u64,
    pub oldest_pending_at: Option<OffsetDateTime>,
    /// The SBOMs whose verdicts are being computed right now, by when they started, with the
    /// (component, vulnerability) groups resolved as their progress.
    #[serde(default)]
    pub current: Vec<CurrentSbom>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExtractionLag {
    /// Pending advisory ingestion events, including failures awaiting retry. SBOMs are
    /// extracted by refresh jobs and counted as `needs_refresh` instead.
    pub pending_advisories: u64,
    /// Pending events that have failed at least once and will be retried.
    pub failed: u64,
    /// Enqueue time of the oldest pending event; null when caught up.
    pub oldest_pending_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FreshnessDocument {
    pub sbom_id: Uuid,
    pub name: String,
    /// The number of packages of the SBOM, as an indication of its size.
    #[serde(default)]
    pub packages: u64,
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
    /// Documents this job still has to process. Zero once the job has finished.
    #[serde(default)]
    pub remaining: u64,
    /// Estimated completion time, extrapolated from the job's average rate so far.
    /// Absent before the first document is processed and once the job has finished.
    #[serde(default)]
    pub estimated_completion_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
    /// The documents an active job is extracting right now, by when they started. Workers of
    /// several instances extract documents of the same job in parallel.
    #[serde(default)]
    pub current: Vec<CurrentSbom>,
}

/// An SBOM being processed right now, e.g. extracted by a refresh job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CurrentSbom {
    pub sbom_id: Uuid,
    /// The name of the SBOM's document node, if known.
    pub name: Option<String>,
    pub started_at: OffsetDateTime,
    /// How far the processing is, if it can tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<WorkProgress>,
}

/// The items of a piece of work done so far, out of all of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WorkProgress {
    pub done: u64,
    /// Zero while the items are still being determined.
    pub total: u64,
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
