use trustify_entity::validation_report;
use utoipa::ToSchema;

/// A stored result of one semantic validator run against one document.
///
/// Reports are append-only, so several may exist for the same document and
/// validator: each one records a result that differed from the one before it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct ValidationReportSummary {
    /// SHA-256 of the validated document, as lowercase hex.
    pub document_sha256: String,
    /// Name of the validator that produced the result.
    pub validator: String,
    /// Whether the validator gated ingestion or only reported.
    #[schema(value_type = String)]
    pub mode: validation_report::Mode,
    /// Whether the document met the validator's threshold.
    #[schema(value_type = String)]
    pub outcome: validation_report::Outcome,
    /// True when this result rejected the document, so nothing was ingested.
    pub blocked: bool,
    /// Highest severity across the findings; absent when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub max_severity: Option<validation_report::Severity>,
    /// Number of findings produced, before truncation.
    pub finding_count: i32,
    /// The findings, as stored. Fewer than `finding_count` when `truncated`.
    pub findings: serde_json::Value,
    /// True when the stored findings were capped.
    pub truncated: bool,
    /// How the document entered the system.
    #[schema(value_type = String)]
    pub ingest_source: validation_report::IngestSource,
    /// Name of the importer, when ingested by one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub importer_name: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub created_at: time::OffsetDateTime,
}

impl From<validation_report::Model> for ValidationReportSummary {
    fn from(value: validation_report::Model) -> Self {
        Self {
            document_sha256: value.document_sha256,
            validator: value.validator,
            mode: value.mode,
            outcome: value.outcome,
            blocked: value.blocked,
            max_severity: value.max_severity,
            finding_count: value.finding_count,
            findings: value.findings,
            truncated: value.truncated,
            ingest_source: value.ingest_source,
            importer_name: value.importer_name,
            created_at: value.created_at,
        }
    }
}
