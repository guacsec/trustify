use crate::runner::http::discovery::{DiscoveredFile, DiscoveryStrategy};
use bytes::Bytes;
use regex::Regex;
use std::{future::Future, sync::Arc};
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
    /// The `PULP_MANIFEST` response body is not valid UTF-8.
    #[error("PULP_MANIFEST at {url} is not valid UTF-8")]
    ManifestEncoding { url: String },
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

/// Returns `true` when `filename` is safe to use as a URL path component.
///
/// Rejects empty strings, absolute paths, and any path segment equal to `..`
/// to prevent path traversal when constructing download URLs.
fn is_safe_filename(filename: &str) -> bool {
    !filename.is_empty()
        && !filename.starts_with('/')
        && !filename.split('/').any(|seg| seg == "..")
}

/// Returns `true` when `digest` is a valid lowercase-or-uppercase 64-character hex string.
fn is_valid_sha256(digest: &str) -> bool {
    digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parses the text body of a `PULP_MANIFEST` CSV into a list of entries.
///
/// The Pulp manifest format is a simple three-column, unquoted CSV
/// (`filename,sha256hex,size_bytes`). Quoted fields and commas inside
/// filenames are not part of the Pulp spec, so a plain split is correct;
/// a Pulp-generated filename never contains a comma.
///
/// Each non-empty line is validated for a non-empty safe filename, a 64-char
/// hex SHA-256, and a parseable non-negative size.
fn parse_manifest(content: &str) -> Result<Vec<ManifestEntry>, Error> {
    let mut entries = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = i + 1;
        let Some((filename_raw, rest)) = line.split_once(',') else {
            return Err(Error::ManifestParse {
                line: line_no,
                content: line.to_string(),
            });
        };
        let Some((sha256_raw, size_str)) = rest.split_once(',') else {
            return Err(Error::ManifestParse {
                line: line_no,
                content: line.to_string(),
            });
        };
        let filename = filename_raw.trim().to_string();
        let sha256 = sha256_raw.trim().to_string();
        let size_str = size_str.trim();

        if !is_safe_filename(&filename) {
            return Err(Error::ManifestParse {
                line: line_no,
                content: line.to_string(),
            });
        }
        if !is_valid_sha256(&sha256) {
            return Err(Error::ManifestParse {
                line: line_no,
                content: line.to_string(),
            });
        }
        let size = size_str.parse::<u64>().map_err(|_| Error::ManifestParse {
            line: line_no,
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

/// Appends the `/`-separated parts of `segment` to `base` using the url crate's
/// `path_segments_mut` API.
///
/// Using `path_segments_mut` rather than string manipulation avoids two hazards:
/// 1. Double-encoding: `url.path()` returns the serialised (percent-encoded) path;
///    concatenating to it and calling `set_path` re-encodes existing `%XX` sequences.
/// 2. Percent-encoded dot traversal: `set_path` would interpret `%2e%2e` as a dot
///    segment and shorten the path; `path_segments_mut().push()` encodes `%` as `%25`,
///    keeping each segment opaque.
fn append_path(base: &Url, segment: &str) -> Url {
    let mut url = base.clone();
    if let Ok(mut segs) = url.path_segments_mut() {
        segs.pop_if_empty();
        segs.extend(segment.split('/').filter(|s| !s.is_empty()));
    }
    url
}

/// Returns the URL for the `PULP_MANIFEST` index at `base`.
fn manifest_url(base: &Url) -> Url {
    append_path(base, "PULP_MANIFEST")
}

/// Returns the download URL for a manifest entry relative to `base`.
fn file_url(base: &Url, filename: &str) -> Url {
    append_path(base, filename)
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
    let name = filename.rsplit_once('/').map_or(filename, |(_, b)| b);
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
    /// Compiled patterns stored in an `Arc` so each `discover()` call increments a
    /// reference count rather than deep-copying every `Regex`.
    only_patterns: Arc<[Regex]>,
}

impl PulpManifest {
    /// Creates a new `PulpManifest` strategy, compiling `only_patterns` as regular expressions.
    ///
    /// Returns an error if any pattern is invalid. Empty `only_patterns` includes all files.
    pub fn new(fetcher: Fetcher, only_patterns: Vec<String>) -> Result<Self, Error> {
        let compiled = only_patterns
            .into_iter()
            .map(|p| {
                p.parse::<Regex>().map_err(|e| Error::InvalidPattern {
                    pattern: p,
                    source: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            fetcher: Arc::new(fetcher),
            only_patterns: compiled.into(),
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
        let patterns = Arc::clone(&self.only_patterns);

        async move {
            let murl = manifest_url(&source);
            let murl_str = murl.to_string();

            let bytes: Bytes =
                fetcher
                    .fetch(murl.as_str())
                    .await
                    .map_err(|e| Error::ManifestFetch {
                        url: murl_str.clone(),
                        source: e,
                    })?;

            let content = std::str::from_utf8(&bytes)
                .map_err(|_| Error::ManifestEncoding { url: murl_str })?;

            let entries = parse_manifest(content)?;

            let files = entries
                .into_iter()
                .filter(|entry| matches_patterns(&entry.filename, &patterns))
                .map(|entry| DiscoveredFile {
                    url: file_url(&source, &entry.filename),
                    sha256: Some(entry.sha256),
                    size: Some(entry.size),
                })
                .collect();

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
        // Given — use valid 64-char hex digests
        let sha1 = "a".repeat(64);
        let sha2 = "b".repeat(64);
        let sha3 = "0".repeat(64);
        let body = format!(
            "Packages/foo.json,{sha1},1024\nPackages/bar.xml,{sha2},2048\nREADME,{sha3},5\n"
        );

        // When
        let entries = parse_manifest(&body).expect("valid manifest should parse");

        // Then
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].filename, "Packages/foo.json");
        assert_eq!(entries[0].sha256, sha1);
        assert_eq!(entries[0].size, 1024);
        assert_eq!(entries[1].filename, "Packages/bar.xml");
        assert_eq!(entries[1].sha256, sha2);
        assert_eq!(entries[1].size, 2048);
        assert_eq!(entries[2].filename, "README");
        assert_eq!(entries[2].size, 5);
    }

    /// Verifies that a malformed `PULP_MANIFEST` line (missing columns) returns
    /// `ManifestParse` with the correct 1-based line number, not a panic.
    #[test]
    fn parse_manifest_malformed_line_returns_error() {
        // Given: second line is malformed
        let body = format!("good.json,{},100\nbad_line\n", "a".repeat(64));

        // When
        let result = parse_manifest(&body);

        // Then
        assert!(
            matches!(result, Err(Error::ManifestParse { line: 2, .. })),
            "expected ManifestParse error for line 2, got: {result:?}"
        );
    }

    /// Verifies that path traversal filenames (`..` segments or absolute paths) are rejected.
    #[test]
    fn parse_manifest_rejects_path_traversal() {
        let sha256 = "a".repeat(64);
        for bad in &["../../etc/passwd", "/etc/passwd", "sub/../secret"] {
            let body = format!("{bad},{sha256},100");
            assert!(
                matches!(parse_manifest(&body), Err(Error::ManifestParse { .. })),
                "expected rejection of filename {bad:?}"
            );
        }
    }

    /// Verifies that an invalid SHA-256 digest (wrong length or non-hex) is rejected.
    #[test]
    fn parse_manifest_rejects_invalid_sha256() {
        for bad_digest in &[
            "abc123",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let body = format!("file.json,{bad_digest},100");
            assert!(
                matches!(parse_manifest(&body), Err(Error::ManifestParse { .. })),
                "expected rejection of digest {bad_digest:?}"
            );
        }
    }

    /// Verifies that a regex pattern `.*\.json$` selects only JSON filenames, and that
    /// empty patterns include all files — matching the existing walker `Filter` semantics.
    #[test]
    fn only_patterns_filters_by_regex() {
        // Given
        let json_re = Regex::new(r".*\.json$").expect("valid regex");
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

    /// Verifies that `file_url` correctly constructs multi-segment paths from manifest
    /// entries with subdirectories, and that `%2e%2e` is not treated as a dot segment.
    #[test]
    fn file_url_constructs_correctly() {
        let base: Url = "https://repo.example.com/pub/".parse().expect("static URL");

        // Multi-segment path
        assert_eq!(
            file_url(&base, "Packages/foo.rpm").as_str(),
            "https://repo.example.com/pub/Packages/foo.rpm"
        );

        // Percent-encoded literal in manifest filename — must NOT be treated as traversal.
        // path_segments_mut encodes % as %25, so %2e%2e becomes %252e%252e (no traversal).
        let traversal_attempt = file_url(&base, "%2e%2e/secret");
        let path = traversal_attempt.path();
        assert!(
            !path.contains("/secret") || path.contains("%252e"),
            "percent-encoded dot segments must not produce path traversal, got: {path}"
        );
    }
}
