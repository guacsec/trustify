/// The result of the ingestion process
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct IngestResult {
    /// The internal ID of the document
    pub id: String,
    /// The ID declared by the document
    pub document_id: Option<String>,
    /// Warnings that occurred during the import process
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}
