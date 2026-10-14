use serde::{Deserialize, Serialize};

/// Request body for ingesting a document from a remote URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IngestFromUrlRequest {
    /// The URL of the document to download and ingest.
    pub url: String,
}
