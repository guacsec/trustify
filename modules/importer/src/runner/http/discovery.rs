use std::future::Future;
use url::Url;

/// A file entry returned by a [`DiscoveryStrategy`].
///
/// Carries the download URL and optional integrity metadata. The shared
/// retrieval layer verifies whatever metadata is present and skips the file
/// if verification fails.
#[derive(Clone, Debug)]
pub struct DiscoveredFile {
    /// URL to download this file.
    pub url: Url,
    /// Expected SHA-256 hex digest, verified after download when present.
    pub sha256: Option<String>,
    /// Expected file size in bytes, verified after download when present.
    pub size: Option<u64>,
}

/// Pluggable file-discovery strategy for the HTTP transport.
///
/// Implementors inspect a source URL and enumerate the available files,
/// returning a [`DiscoveredFile`] entry per file with its download URL and
/// optional integrity metadata (SHA-256 digest and/or size).
pub trait DiscoveryStrategy: Send + Sync {
    /// Enumerate files available at `source`.
    fn discover(
        &self,
        source: &Url,
    ) -> impl Future<Output = anyhow::Result<Vec<DiscoveredFile>>> + Send;
}
