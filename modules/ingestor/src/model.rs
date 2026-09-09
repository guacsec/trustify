use crate::service::validation::ValidationReport;
use trustify_common::id::Id;

/// The result of the ingestion process
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct IngestResult {
    #[schema(value_type = Id)]
    /// The internal ID of the document
    pub id: String,
    /// The ID declared by the document
    pub document_id: Option<String>,
    /// Warnings that occurred during the import process
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Structured reports from semantic validators run during ingestion.
    ///
    /// See ADR 00020. Empty when no validators are configured or none apply
    /// to the document's format.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation: Vec<ValidationReport>,
}
