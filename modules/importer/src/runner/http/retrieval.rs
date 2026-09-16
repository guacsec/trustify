use crate::runner::{
    http::{discovery::DiscoveredFile, error::Error},
    report::{Phase, ReportBuilder},
};
use bytes::Bytes;
use parking_lot::Mutex;
use sha2::{Digest as _, Sha256};
use std::{future::Future, sync::Arc};
use walker_common::fetcher::Fetcher;

/// Compute the lowercase hex SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Verify the SHA-256 digest and size of `data` against the metadata in `file`.
///
/// Returns `Ok(())` when all present integrity fields match. On the first
/// mismatch, returns a typed [`Error`]; the caller records the error and skips
/// the file.
pub fn verify_integrity(data: &[u8], file: &DiscoveredFile) -> Result<(), Error> {
    if let Some(expected_size) = file.size {
        let actual_size = data.len() as u64;
        if actual_size != expected_size {
            return Err(Error::SizeMismatch {
                url: file.url.to_string(),
                expected: expected_size,
                actual: actual_size,
            });
        }
    }

    if let Some(ref expected_sha256) = file.sha256 {
        let actual_hex = sha256_hex(data);
        if *expected_sha256 != actual_hex {
            return Err(Error::DigestMismatch {
                url: file.url.to_string(),
                expected: expected_sha256.clone(),
                actual: actual_hex,
            });
        }
    }

    Ok(())
}

/// Fetch, integrity-verify, and process every file in `files`.
///
/// For each file the shared retrieval layer:
/// 1. Downloads the file via `fetcher` (with its configured retries and
///    exponential back-off).
/// 2. Verifies SHA-256 and/or size when the [`DiscoveredFile`] provides them.
/// 3. On success, calls `on_file(bytes, file)` so the caller can delegate to
///    the ingestor with the appropriate labels, format hint, and credentials
///    without coupling this layer to the importer configuration.
///
/// Any fetch or integrity error is recorded in `report` and the file is
/// skipped; processing continues for the remaining files. Errors returned by
/// `on_file` (e.g. ingestion failures) are similarly recorded and do not abort
/// the loop.
pub async fn retrieve_files<F, Fut>(
    fetcher: &Fetcher,
    files: Vec<DiscoveredFile>,
    on_file: F,
    report: Arc<Mutex<ReportBuilder>>,
) where
    F: Fn(Bytes, DiscoveredFile) -> Fut + Send + Sync,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    for file in files {
        let url_str = file.url.to_string();

        let data: Bytes = match fetcher.fetch(file.url.as_str()).await {
            Ok(b) => b,
            Err(err) => {
                report.lock().add_error(
                    Phase::Retrieval,
                    &url_str,
                    Error::Fetch {
                        url: url_str.clone(),
                        source: err,
                    }
                    .to_string(),
                );
                continue;
            }
        };

        if let Err(err) = verify_integrity(&data, &file) {
            report
                .lock()
                .add_error(Phase::Validation, &url_str, err.to_string());
            continue;
        }

        match on_file(data, file).await {
            Ok(()) => report.lock().tick(),
            Err(err) => report
                .lock()
                .add_error(Phase::Upload, &url_str, err.to_string()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::runner::http::discovery::DiscoveredFile;
    use parking_lot::Mutex;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use walker_common::fetcher::FetcherOptions;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    /// Verifies that `verify_integrity` passes when the SHA-256 digest matches.
    #[test]
    fn integrity_passes_matching_sha256() {
        let data = b"hello world";
        let expected = sha256_hex(data);
        let file = DiscoveredFile {
            url: "http://example.com/f".parse().expect("static URL is valid"),
            sha256: Some(expected),
            size: None,
        };
        assert!(verify_integrity(data, &file).is_ok());
    }

    /// Verifies that `verify_integrity` returns `DigestMismatch` when the
    /// SHA-256 digest does not match the downloaded content.
    #[test]
    fn integrity_fails_mismatching_sha256() {
        let data = b"hello world";
        let file = DiscoveredFile {
            url: "http://example.com/f".parse().expect("static URL is valid"),
            sha256: Some("deadbeef".to_string()),
            size: None,
        };
        // Given
        let err = verify_integrity(data, &file).expect_err("should fail on digest mismatch");
        // Then
        assert!(
            matches!(err, Error::DigestMismatch { .. }),
            "expected DigestMismatch, got {err}"
        );
    }

    /// Verifies that `verify_integrity` returns `SizeMismatch` when the
    /// declared size does not match the actual byte count.
    #[test]
    fn integrity_fails_mismatching_size() {
        // Given
        let data = b"hello";
        let file = DiscoveredFile {
            url: "http://example.com/f".parse().expect("static URL is valid"),
            sha256: None,
            size: Some(99),
        };
        // When
        let err = verify_integrity(data, &file).expect_err("should fail on size mismatch");
        // Then
        assert!(
            matches!(err, Error::SizeMismatch { .. }),
            "expected SizeMismatch, got {err}"
        );
    }

    /// Verifies that `retrieve_files` records a retrieval error in the report
    /// and does not call `on_file` when the server returns an error response.
    /// Retry-exhaustion behavior is provided by `walker_common::fetcher::Fetcher`.
    #[tokio::test]
    async fn fetch_failure_records_error_in_report() {
        // Given a mock server that always returns 500
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/file.txt"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1..)
            .mount(&server)
            .await;

        let url: url::Url = format!("{}/file.txt", server.uri())
            .parse()
            .expect("valid URL");
        let file = DiscoveredFile {
            url,
            sha256: None,
            size: None,
        };

        // When: fetcher with 0 retries so the test completes quickly
        let fetcher = Fetcher::new(FetcherOptions::new().retries(0))
            .await
            .expect("fetcher creation succeeds");
        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let on_file_called = Arc::new(AtomicBool::new(false));
        let on_file_called_clone = Arc::clone(&on_file_called);

        retrieve_files(
            &fetcher,
            vec![file],
            move |_bytes, _file| {
                on_file_called_clone.store(true, Ordering::SeqCst);
                async { Ok(()) }
            },
            Arc::clone(&report),
        )
        .await;

        // Then: error is recorded, on_file is never called
        let built = report.lock().clone().build();
        assert!(
            !built.messages.is_empty(),
            "expected at least one error recorded in report"
        );
        assert!(
            !on_file_called.load(Ordering::SeqCst),
            "on_file should not be called on fetch failure"
        );
    }
}
