use crate::runner::http::discovery::{DiscoveredFile, DiscoveryStrategy};
use bytes::Bytes;
use regex::Regex;
use std::{future::Future, str::FromStr, sync::Arc};
use url::Url;
use walker_common::fetcher::{self, Fetcher};

/// Errors produced by the Pulp Manifest discovery strategy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to fetch the `PULP_MANIFEST` index from the source repository.
    #[error("failed to fetch PULP_MANIFEST from {url}: {source}")]
    ManifestFetch {
        url: String,
        #[source]
        source: fetcher::Error,
    },
    /// A line in `PULP_MANIFEST` does not conform to the expected `filename,sha256,size` format.
    #[error("malformed PULP_MANIFEST line {line}: {content:?}")]
    ManifestParse {
        /// 1-based line number of the offending line.
        line: usize,
        /// Raw text of the offending line.
        content: String,
    },
    /// A supplied regex pattern could not be compiled.
    #[error("invalid pattern '{pattern}': {source}")]
    InvalidPattern {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// A single parsed entry from a `PULP_MANIFEST` CSV file.
#[derive(Debug)]
struct ManifestEntry {
    filename: String,
    sha256: String,
    size: u64,
}

/// Parses the text body of a `PULP_MANIFEST` CSV into a list of entries.
///
/// Each non-empty line must be of the form `filename,sha256hex,size_bytes`.
fn parse_manifest(content: &str) -> Result<Vec<ManifestEntry>, Error> {
    let mut entries = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() != 3 {
            return Err(Error::ManifestParse {
                line: i + 1,
                content: line.to_string(),
            });
        }
        let filename = parts[0].trim().to_string();
        let sha256 = parts[1].trim().to_string();
        let size = parts[2]
            .trim()
            .parse::<u64>()
            .map_err(|_| Error::ManifestParse {
                line: i + 1,
                content: line.to_string(),
            })?;
        entries.push(ManifestEntry {
            filename,
            sha256,
            size,
        });
    }
    Ok(entries)
}

/// Appends `PULP_MANIFEST` to `base`, ensuring exactly one `/` separator.
fn manifest_url(base: &Url) -> Url {
    let mut url = base.clone();
    let mut path = url.path().to_owned();
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str("PULP_MANIFEST");
    url.set_path(&path);
    url
}

/// Constructs the download URL for a manifest entry by appending `filename` to `base`.
fn file_url(base: &Url, filename: &str) -> Url {
    let mut url = base.clone();
    let mut path = url.path().to_owned();
    if !path.ends_with('/') {
        path.push('/');
    }
    let filename = filename.trim_start_matches('/');
    path.push_str(filename);
    url.set_path(&path);
    url
}

/// Returns `true` when `filename` matches at least one compiled regex in `patterns`,
/// or when `patterns` is empty (include-all semantics).
///
/// Matching is performed against the basename (last path segment) of `filename`,
/// mirroring the behaviour of the existing walker `Filter`.
fn matches_patterns(filename: &str, patterns: &[Regex]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let name = filename.rsplit('/').next().unwrap_or(filename);
    patterns.iter().any(|p| p.is_match(name))
}

/// Discovery strategy that reads a Pulp repository's `PULP_MANIFEST` index.
///
/// Fetches `{source}/PULP_MANIFEST`, parses each CSV line into a [`DiscoveredFile`]
/// with SHA-256 and size integrity metadata, and applies optional regex `only_patterns`
/// filtering (same semantics as the existing walker `Filter`) before returning the list
/// to the shared retrieval layer.
pub struct PulpManifest {
    fetcher: Arc<Fetcher>,
    only_patterns: Vec<Regex>,
}

impl PulpManifest {
    /// Creates a new `PulpManifest` strategy, compiling `only_patterns` as regular expressions.
    ///
    /// Returns an error if any pattern is invalid. Empty `only_patterns` includes all files.
    pub fn new(fetcher: Fetcher, only_patterns: Vec<String>) -> Result<Self, Error> {
        let compiled = only_patterns
            .into_iter()
            .map(|p| {
                Regex::from_str(&p).map_err(|e| Error::InvalidPattern {
                    pattern: p,
                    source: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            fetcher: Arc::new(fetcher),
            only_patterns: compiled,
        })
    }
}

impl DiscoveryStrategy for PulpManifest {
    fn discover(
        &self,
        source: &Url,
    ) -> impl Future<Output = anyhow::Result<Vec<DiscoveredFile>>> + Send {
        let fetcher = Arc::clone(&self.fetcher);
        let source = source.clone();
        let patterns = self.only_patterns.clone();

        async move {
            let murl = manifest_url(&source);
            let murl_str = murl.to_string();

            let bytes: Bytes =
                fetcher
                    .fetch(murl.as_str())
                    .await
                    .map_err(|e| Error::ManifestFetch {
                        url: murl_str,
                        source: e,
                    })?;

            let content = String::from_utf8_lossy(&bytes);
            let entries = parse_manifest(&content)?;

            let mut files = Vec::with_capacity(entries.len());
            for entry in entries {
                if !matches_patterns(&entry.filename, &patterns) {
                    continue;
                }
                let url = file_url(&source, &entry.filename);
                files.push(DiscoveredFile {
                    url,
                    sha256: Some(entry.sha256),
                    size: Some(entry.size),
                });
            }

            Ok(files)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Verifies that a well-formed `PULP_MANIFEST` body produces the expected entries
    /// with correct filename, sha256, and size values.
    #[test]
    fn parse_manifest_produces_expected_entries() {
        // Given
        let body = "\
Packages/foo.json,abc123,1024\n\
Packages/bar.xml,def456,2048\n\
README,000000,5\n";

        // When
        let entries = parse_manifest(body).expect("valid manifest should parse");

        // Then
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].filename, "Packages/foo.json");
        assert_eq!(entries[0].sha256, "abc123");
        assert_eq!(entries[0].size, 1024);
        assert_eq!(entries[1].filename, "Packages/bar.xml");
        assert_eq!(entries[1].sha256, "def456");
        assert_eq!(entries[1].size, 2048);
        assert_eq!(entries[2].filename, "README");
        assert_eq!(entries[2].size, 5);
    }

    /// Verifies that a malformed `PULP_MANIFEST` line (missing columns) returns
    /// `ManifestParse` with the correct 1-based line number, not a panic.
    #[test]
    fn parse_manifest_malformed_line_returns_error() {
        // Given: second line is malformed
        let body = "good.json,abc,100\nbad_line\n";

        // When
        let result = parse_manifest(body);

        // Then
        assert!(
            matches!(result, Err(Error::ManifestParse { line: 2, .. })),
            "expected ManifestParse error for line 2, got: {result:?}"
        );
    }

    /// Verifies that a regex pattern `.*\.json$` selects only JSON filenames, and that
    /// empty patterns include all files — matching the existing walker `Filter` semantics.
    #[test]
    fn only_patterns_filters_by_regex() {
        // Given
        let json_re = Regex::from_str(r".*\.json$").expect("valid regex");
        let filenames = ["Packages/foo.json", "Packages/bar.xml", "README"];

        // When: .*\.json$ pattern applied
        let matched: Vec<_> = filenames
            .iter()
            .filter(|f| matches_patterns(f, std::slice::from_ref(&json_re)))
            .copied()
            .collect();

        // Then: only the JSON file matches
        assert_eq!(matched, vec!["Packages/foo.json"]);

        // When: empty patterns (include-all)
        let all: Vec<_> = filenames
            .iter()
            .filter(|f| matches_patterns(f, &[]))
            .copied()
            .collect();

        // Then: all three files are included
        assert_eq!(all.len(), 3);
    }

    /// Verifies that `manifest_url` appends `PULP_MANIFEST` with a single `/` separator
    /// regardless of whether the source URL already ends with `/`.
    #[test]
    fn manifest_url_appends_correctly() {
        let with_slash: Url = "https://repo.example.com/pub/".parse().expect("static URL");
        let without_slash: Url = "https://repo.example.com/pub".parse().expect("static URL");

        assert_eq!(
            manifest_url(&with_slash).as_str(),
            "https://repo.example.com/pub/PULP_MANIFEST"
        );
        assert_eq!(
            manifest_url(&without_slash).as_str(),
            "https://repo.example.com/pub/PULP_MANIFEST"
        );
    }
}
