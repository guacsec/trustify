/// Errors produced by the HTTP transport layer.
pub mod error;

/// Pluggable file-discovery strategy trait and discovered-file entry type.
pub mod discovery;

mod retrieval;

pub use discovery::{DiscoveredFile, DiscoveryStrategy};
pub use retrieval::{retrieve_files, sha256_hex, verify_integrity};
