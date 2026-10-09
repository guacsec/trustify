use sea_orm::entity::prelude::*;

/// The result of one semantic validator run against one document.
///
/// Rows are append-only: a run inserts a row only when its result differs from
/// the latest stored one for the same `(document_sha256, validator)`. The
/// current result is therefore the row with the greatest `created_at`, and
/// older rows are the history of how that verdict changed.
///
/// Documents rejected by a `verify` validator are recorded with
/// `blocked = true`. Those never reach storage, so there is no `source_document`
/// row to reference — the digest is the only link to the document.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "validation_report")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    /// SHA-256 of the raw document, as lowercase hex.
    pub document_sha256: String,
    /// The [`crate::validation_report::Model::validator`] name from configuration.
    pub validator: String,
    /// Whether the validator gated ingestion or only reported.
    pub mode: Mode,
    /// Whether the document met the validator's threshold.
    pub outcome: Outcome,
    /// True when this run rejected the document, so nothing was ingested.
    pub blocked: bool,
    /// Highest severity across the findings; `None` when there are none.
    pub max_severity: Option<Severity>,
    /// Number of findings produced, before truncation.
    pub finding_count: i32,
    /// The findings, as a JSON array; truncated to the configured caps.
    pub findings: serde_json::Value,
    /// True when `findings` holds fewer entries than `finding_count`.
    pub truncated: bool,
    /// Digest of the result, used to detect that a re-run changed nothing.
    pub content_hash: String,
    /// Digest of the validator configuration that produced this result.
    pub config_fingerprint: String,
    /// How the document entered the system.
    pub ingest_source: IngestSource,
    /// Name of the importer, when `ingest_source` is [`IngestSource::Importer`].
    pub importer_name: Option<String>,
    pub created_at: time::OffsetDateTime,
}

/// Whether a validator gates ingestion or only records findings.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    strum::Display,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "validation_mode")]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum Mode {
    /// Findings are recorded but never block ingestion.
    #[sea_orm(string_value = "report")]
    Report,
    /// A failing outcome blocks ingestion.
    #[sea_orm(string_value = "verify")]
    Verify,
}

/// Whether a validator considered the document acceptable.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    strum::Display,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "validation_outcome")]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum Outcome {
    /// No finding met the validator's blocking threshold.
    #[sea_orm(string_value = "passed")]
    Passed,
    /// At least one finding met the validator's blocking threshold.
    #[sea_orm(string_value = "failed")]
    Failed,
}

/// Severity of a validation finding.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    strum::Display,
)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "validation_severity"
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum Severity {
    #[sea_orm(string_value = "info")]
    Info,
    #[sea_orm(string_value = "warning")]
    Warning,
    #[sea_orm(string_value = "error")]
    Error,
    #[sea_orm(string_value = "fatal")]
    Fatal,
}

/// How a document entered the system.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumIter,
    DeriveActiveEnum,
    serde::Serialize,
    serde::Deserialize,
    strum::Display,
)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "validation_ingest_source"
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum IngestSource {
    /// Uploaded through the API.
    #[sea_orm(string_value = "api")]
    Api,
    /// Fetched by an importer run.
    #[sea_orm(string_value = "importer")]
    Importer,
    /// Loaded as part of a dataset archive.
    #[sea_orm(string_value = "dataset")]
    Dataset,
    /// Ingested by internal code, including tests.
    #[sea_orm(string_value = "internal")]
    Internal,
}

/// Relation to [`super::source_document`] by digest.
///
/// This is a query-time join only — there is deliberately no foreign key in the
/// schema, because reports are also written for rejected documents, which never
/// get a `source_document` row.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::source_document::Entity"
        from = "Column::DocumentSha256"
        to = "super::source_document::Column::Sha256")]
    SourceDocument,
}

impl Related<super::source_document::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SourceDocument.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;
    use test_log::test;

    #[test]
    fn severity_ordering_and_strings() {
        assert!(Severity::Fatal > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);

        for (s, severity) in [
            ("info", Severity::Info),
            ("warning", Severity::Warning),
            ("error", Severity::Error),
            ("fatal", Severity::Fatal),
        ] {
            assert_eq!(severity.to_string(), s);
            assert_eq!(json!(severity), json!(s));
        }
    }

    #[test]
    fn enum_strings() {
        assert_eq!(json!(Mode::Verify), json!("verify"));
        assert_eq!(json!(Outcome::Failed), json!("failed"));
        assert_eq!(json!(IngestSource::Importer), json!("importer"));
    }
}
