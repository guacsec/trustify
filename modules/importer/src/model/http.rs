use crate::model::{CommonImporter, auth::AuthConfig};
use std::ops::{Deref, DerefMut};
use utoipa::ToSchema;

/// Configuration for the HTTP-based importer.
///
/// Fetches documents from an HTTP repository, using a pluggable
/// discovery strategy to enumerate files and an optional credential
/// for authenticated sources.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct HttpImporter {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// Base URL of the HTTP repository to import documents from.
    pub source: String,

    /// File-discovery strategy used to enumerate files in the source.
    pub discovery: HttpDiscovery,

    /// Optional authentication configuration for accessing the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,

    /// Optional list of regex patterns restricting which discovered files are
    /// imported. An empty list imports all discovered files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_patterns: Vec<String>,

    /// Number of fetch retries for individual file downloads.
    /// Defaults to the fetcher's built-in retry count when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_retries: Option<usize>,
}

impl Deref for HttpImporter {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for HttpImporter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

/// Pluggable file-discovery strategy for the HTTP importer.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum HttpDiscovery {
    /// Discover files using the Pulp repository `PULP_MANIFEST` index.
    Pulp,
}
