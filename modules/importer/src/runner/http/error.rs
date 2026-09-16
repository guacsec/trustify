use walker_common::fetcher;

/// Errors produced by the HTTP transport retrieval layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP fetch failed (after exhausting all retries).
    #[error("fetch failed for {url}: {source}")]
    Fetch {
        /// URL that failed to fetch.
        url: String,
        #[source]
        source: fetcher::Error,
    },
    /// Downloaded content SHA-256 digest does not match the expected value.
    #[error("SHA-256 mismatch for {url}: expected {expected}, got {actual}")]
    DigestMismatch {
        /// URL of the file whose digest mismatched.
        url: String,
        /// Expected hex digest as provided by the discovery strategy.
        expected: String,
        /// Actual hex digest computed from the downloaded bytes.
        actual: String,
    },
    /// Downloaded content size does not match the expected value.
    #[error("size mismatch for {url}: expected {expected} bytes, got {actual} bytes")]
    SizeMismatch {
        /// URL of the file whose size mismatched.
        url: String,
        /// Expected size in bytes as provided by the discovery strategy.
        expected: u64,
        /// Actual size in bytes after downloading.
        actual: u64,
    },
}
