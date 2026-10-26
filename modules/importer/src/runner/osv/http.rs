//! OSV.dev's REST-source convention: an index of id/modified pairs and
//! individual OSV records at <base>/<id>.json.
use super::Context;
use crate::runner::{
    context::RunContext,
    progress::{Progress, ProgressInstance},
    report::Phase,
};
use anyhow::{Context as _, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_slice, from_value, to_value, to_vec};
use sha2::{Digest as _, Sha256};
use std::{collections::HashSet, time::Duration};
use tokio::{select, time::sleep};
use trustify_module_ingestor::service::advisory::osv::parse;
use url::Url;
use walker_common::{
    USER_AGENT,
    fetcher::{DataProcessor, Fetcher},
};

const INDEX_LIMIT: usize = 256 * 1024 * 1024;
const RECORD_LIMIT: usize = 16 * 1024 * 1024;
const CONCURRENCY: usize = 8;

pub(super) fn feed_urls(source: &str, base_url: Option<&Url>) -> anyhow::Result<(Url, Url)> {
    let source = Url::parse(source).context("invalid OSV HTTP index URL")?;
    ensure_http(&source)?;
    let mut base = base_url.cloned().unwrap_or(source.join("./")?);
    ensure_http(&base)?;
    ensure!(
        base.query().is_none() && base.fragment().is_none(),
        "OSV baseUrl must not contain a query or fragment"
    );
    if !base.path().ends_with('/') {
        base.path_segments_mut()
            .map_err(|_| anyhow!("invalid OSV baseUrl"))?
            .push("");
    }
    Ok((source, base))
}

fn ensure_http(url: &Url) -> anyhow::Result<()> {
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "OSV REST URLs must use HTTP or HTTPS"
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    modified: DateTime<Utc>,
}

fn record_url(base: &Url, id: &str) -> anyhow::Result<Url> {
    // Never let an untrusted ID change the origin, directory, or query.
    ensure!(
        !id.is_empty()
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b":_.-".contains(&c)),
        "invalid OSV record ID: {id}"
    );
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| anyhow!("invalid OSV baseUrl"))?
        .pop_if_empty()
        .push(&format!("{id}.json"));
    Ok(url)
}

/// Only a successful scan advances the watermark to its start time. Settings
/// changes (and legacy blob continuations) trigger a full scan.
#[derive(Serialize, Deserialize)]
struct Continuation {
    osv_http_v2: DateTime<Utc>,
    settings: String,
}

struct HttpFetcher {
    fetcher: Fetcher,
    index: Url,
    base: Url,
}

impl HttpFetcher {
    fn new(index: Url, base: Url) -> anyhow::Result<Self> {
        Ok(Self {
            // Use default TLS trust, the walker user agent, and Fetcher's
            // retry/rate-limit policy.
            fetcher: Fetcher::from(
                Client::builder()
                    .user_agent(USER_AGENT)
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(30))
                    .build()?,
            ),
            index,
            base,
        })
    }

    async fn index(&self) -> anyhow::Result<Vec<Entry>> {
        from_slice(&self.fetch(&self.index, INDEX_LIMIT).await?).context("invalid OSV REST index")
    }

    async fn record(&self, id: &str) -> anyhow::Result<Vec<u8>> {
        let url = record_url(&self.base, id)?;
        self.fetch(&url, RECORD_LIMIT).await
    }

    async fn fetch(&self, url: &Url, limit: usize) -> anyhow::Result<Vec<u8>> {
        self.fetcher
            .fetch_processed(url.clone(), LimitedBytes(limit))
            .await?
    }
}

/// Keep the generic fetcher's status checks/retries while bounding memory for
/// both index and record bodies. Size errors are terminal, not retryable.
struct LimitedBytes(usize);

impl DataProcessor for LimitedBytes {
    type Type = anyhow::Result<Vec<u8>>;

    async fn process(&self, response: Response) -> Result<Self::Type, reqwest::Error> {
        let mut response = response.error_for_status()?;
        let limit = self.0;
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Ok(Err(anyhow!("OSV response exceeds size limit")));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Ok(Err(anyhow!("OSV response exceeds size limit")));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Ok(bytes))
    }
}

pub(super) struct HttpWalker<C: RunContext + 'static> {
    context: Context<C>,
    fetcher: HttpFetcher,
    continuation: Option<Continuation>,
}

async fn wait_for_cancellation(context: &impl RunContext) {
    loop {
        if context.is_canceled().await {
            return;
        }
        sleep(Duration::from_secs(1)).await;
    }
}

impl<C: RunContext> HttpWalker<C> {
    pub(super) fn new(
        context: Context<C>,
        index: Url,
        base: Url,
        continuation: Value,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            context,
            fetcher: HttpFetcher::new(index, base)?,
            continuation: from_value(continuation).ok(),
        })
    }

    pub(super) async fn run(self) -> anyhow::Result<(Option<Value>, Option<anyhow::Error>)> {
        let Self {
            context,
            fetcher,
            continuation,
        } = self;
        let index = &fetcher.index;
        let base = &fetcher.base;
        let mut years: Vec<_> = context.years.iter().copied().collect();
        years.sort_unstable();
        let labels = to_value(&context.labels)?;
        let settings: String = Sha256::digest(to_vec(&(
            index.as_str(),
            base.as_str(),
            years,
            context.start_year,
            labels,
        ))?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
        let continuation = continuation.filter(|previous| previous.settings == settings);
        context
            .context
            .check_canceled(|| anyhow!("OSV import canceled"))
            .await?;
        // Scope each cancellation future to its select: a pending check can hold
        // the context's mutex, which later direct checks must be able to acquire.
        // Capture before requesting the index, not after finishing ingestion:
        // records published during this scan must remain eligible next time.
        // Backdated records still require a full rescan to discover.
        let started = Utc::now();
        let entries = select! {
            entries = fetcher.index() => entries?,
            () = wait_for_cancellation(&context.context) => bail!("OSV import canceled"),
        };
        // Validate the entire index before processing anything. Duplicate IDs make
        // checkpoint semantics ambiguous, even if their timestamps happen to agree.
        let mut seen = HashSet::new();
        for entry in &entries {
            record_url(base, &entry.id)?;
            ensure!(
                seen.insert(entry.id.as_str()),
                "duplicate OSV index ID: {}",
                entry.id
            );
        }
        let changed: Vec<_> = entries
            .iter()
            .filter(|entry| {
                continuation
                    .as_ref()
                    .is_none_or(|previous| entry.modified >= previous.osv_http_v2)
            })
            .collect();
        let progress = context
            .context
            .progress(format!("Import OSV HTTP: {index}"));
        let mut progress = progress.start(changed.len());
        let mut downloads = stream::iter(changed.into_iter().map(|entry| {
            let fetcher = &fetcher;
            async move { (entry, fetcher.record(&entry.id).await) }
        }))
        .buffer_unordered(CONCURRENCY);
        let mut error = None;
        loop {
            let result = select! {
                result = downloads.next() => match result {
                    Some(result) => result,
                    None => break,
                },
                () = wait_for_cancellation(&context.context) => {
                    error = Some(anyhow!("OSV import canceled"));
                    break;
                }
            };
            if context.context.is_canceled().await {
                error = Some(anyhow!("OSV import canceled"));
                break;
            }
            let (entry, data) = result;
            let url = record_url(base, &entry.id)?;
            let (phase, result) = match data {
                Ok(data) => {
                    // Catch mismatched or malformed records even when a year filter
                    // would otherwise skip ingestion.
                    let result = async {
                        let document = parse(&data)?;
                        ensure!(
                            document.id == entry.id,
                            "OSV record ID does not match index"
                        );
                        ensure!(
                            document.modified >= entry.modified,
                            "OSV record is older than index entry"
                        );
                        // A newer document is safe to ingest: the scan-start
                        // watermark keeps changes during this scan eligible next time.
                        context.store(url.as_str(), &data).await
                    }
                    .await;
                    (Phase::Upload, result)
                }
                Err(err) => (Phase::Retrieval, Err(err)),
            };
            if let Err(err) = result {
                context
                    .report
                    .lock()
                    .add_error(phase, url.as_str(), err.to_string());
                error = Some(anyhow!("some OSV records failed; see import report"));
            }
            progress.tick().await;
        }
        drop(downloads);
        progress.finish().await;
        if error.is_none() && context.context.is_canceled().await {
            error = Some(anyhow!("OSV import canceled"));
        }
        let continuation = if error.is_none() {
            Some(Continuation {
                osv_http_v2: started,
                settings,
            })
        } else {
            continuation
        };
        let continuation = to_value(continuation)?;
        Ok((Some(continuation), error))
    }
}

#[cfg(test)]
mod tests {
    use super::super::handler::OsvHandler;
    use super::*;
    use crate::{
        model::{OsvImporter, auth::CredentialConfig},
        runner::{
            ImportRunner,
            common::walker::GitWalker,
            report::{ReportBuilder, SplitScannerError},
        },
    };
    use chrono::TimeDelta;
    use git2::{Repository, Signature};
    use parking_lot::Mutex;
    use rstest::rstest;
    use serde_json::json;
    use std::{
        fs::write,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use test_context::test_context;
    use tokio::time::timeout;
    use trustify_common::db::ReadWrite;
    use trustify_module_ingestor::{graph::Graph, service::IngestorService};
    use trustify_test_context::TrustifyContext;
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn importer(source: &str) -> OsvImporter {
        from_value(json!({"source": source, "period": "1h", "transport": "http"})).unwrap()
    }

    #[rstest]
    #[case::conventional_index("https://example.com/osv/all.json")]
    #[case::http_with_query("http://localhost/all.json?token=secret")]
    #[case::extensionless_index("https://example.com/index")]
    #[case::arbitrary_filename("https://example.com/feed.json")]
    fn http_index_urls(#[case] source: &str) {
        assert_eq!(feed_urls(source, None).unwrap().0.as_str(), source);
    }

    #[rstest]
    #[case::git("git@example.com:org/repo")]
    #[case::local("/local/repo")]
    #[case::file("file:///all.json")]
    fn non_http_index_urls_are_rejected(#[case] source: &str) {
        assert!(feed_urls(source, None).is_err());
    }

    #[test]
    fn base_url_override() {
        let (_, base) = feed_urls(
            "https://example.com/index",
            Some(&Url::parse("https://records.example.com/osv").unwrap()),
        )
        .unwrap();
        assert_eq!(
            record_url(&base, "OSV-2026-1234").unwrap().as_str(),
            "https://records.example.com/osv/OSV-2026-1234.json"
        );
    }

    #[rstest]
    #[case::empty("")]
    #[case::traversal("../escape")]
    #[case::absolute("https://evil.test/")]
    #[case::origin_relative("//evil.test")]
    #[case::query("a?b")]
    #[case::fragment("a#b")]
    #[case::encoded_slash("a%2fb")]
    #[case::backslash("a\\b")]
    fn untrusted_ids_cannot_escape_base(#[case] id: &str) {
        let base = Url::parse("https://example.com/osv/").unwrap();
        assert!(record_url(&base, id).is_err(), "{id}");
    }

    #[test]
    fn record_id_with_namespace() {
        let base = Url::parse("https://example.com/osv/").unwrap();
        assert_eq!(
            record_url(&base, "DB:123").unwrap().as_str(),
            "https://example.com/osv/DB:123.json"
        );
    }

    #[tokio::test]
    async fn fetch_checks_status_and_size() {
        let server = MockServer::start().await;
        Mock::given(path("/error"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string("12345"))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).unwrap();
        let fetcher = HttpFetcher::new(url.clone(), url).unwrap();
        assert!(
            fetcher
                .fetch(&Url::parse(&format!("{}/error", server.uri())).unwrap(), 10)
                .await
                .unwrap_err()
                .to_string()
                .contains("404")
        );
        assert!(
            fetcher
                .fetch(&Url::parse(&format!("{}/big", server.uri())).unwrap(), 4)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn shared_fetcher_retries_server_errors() {
        let server = MockServer::start().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        Mock::given(path("/all.json"))
            .and(header("user-agent", USER_AGENT))
            .respond_with(move |_: &Request| {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    ResponseTemplate::new(200).set_body_json(json!([]))
                }
            })
            .mount(&server)
            .await;
        let index = Url::parse(&format!("{}/all.json", server.uri())).unwrap();
        let fetcher = HttpFetcher::new(index.clone(), index.join("./").unwrap()).unwrap();
        assert!(fetcher.index().await.unwrap().is_empty());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    fn runner(ctx: &TrustifyContext) -> ImportRunner {
        ImportRunner {
            db: ReadWrite::new(ctx.db.clone()),
            storage: ctx.storage.clone().into(),
            working_dir: None,
            analysis: None,
            credential_config: CredentialConfig::default(),
        }
    }

    async fn serve(server: &MockServer, entries: &[(&str, &str)], fail: Option<&str>) {
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/all.json"))
            .and(header("user-agent", USER_AGENT))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    entries
                        .iter()
                        .map(|(id, modified)| json!({"id": id, "modified": modified}))
                        .collect::<Vec<_>>(),
                ),
            )
            .mount(server)
            .await;
        for (id, modified) in entries {
            let response = if fail == Some(*id) {
                ResponseTemplate::new(404)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "schema_version": "1.7.5", "id": id, "modified": modified,
                    "published": "2024-01-01T00:00:00Z", "summary": "test advisory"
                }))
            };
            Mock::given(method("GET"))
                .and(path(format!("/{id}.json")))
                .and(header("user-agent", USER_AGENT))
                .respond_with(response)
                .mount(server)
                .await;
        }
    }

    #[test_context(TrustifyContext)]
    #[tokio::test]
    async fn incremental_and_partial_failure(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        let first = [("OSV-2026-0001", "2026-01-01T00:00:00Z")];
        serve(&server, &first, Some(first[0].0)).await;
        let (output, result) = runner
            .run_once_osv((), config.clone(), Value::Null)
            .await
            .split()?;
        assert!(result.is_err());
        assert_eq!(output.continuation, Some(Value::Null));
        serve(&server, &first, None).await;
        let output = runner.run_once_osv((), config.clone(), Value::Null).await?;
        assert_eq!(output.report.number_of_items, 1);
        let token = output.continuation.unwrap();
        assert!(to_vec(&token)?.len() < 200);
        let output = runner
            .run_once_osv((), config.clone(), token.clone())
            .await?;
        assert_eq!(output.report.number_of_items, 0);
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.url.path() != "/all.json")
                .count(),
            1
        );
        let watermark = from_value::<Continuation>(token.clone())?.osv_http_v2;
        let boundary = watermark.to_rfc3339();
        let newer = (watermark + TimeDelta::seconds(1)).to_rfc3339();
        let next = [
            (first[0].0, boundary.as_str()),
            ("OSV-2020-0002", "2020-01-01T00:00:00Z"),
            ("OSV-2026-0003", newer.as_str()),
        ];
        serve(&server, &next, Some(next[2].0)).await;
        let (output, result) = runner
            .run_once_osv((), config.clone(), token.clone())
            .await
            .split()?;
        assert!(result.is_err());
        assert_eq!(output.report.number_of_items, 1);
        assert_eq!(output.continuation.as_ref(), Some(&token));
        serve(&server, &next, None).await;
        let output = runner.run_once_osv((), config.clone(), token).await?;
        assert_eq!(output.report.number_of_items, 2);
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.url.path() != "/all.json")
                .count(),
            2
        );
        // Legacy blob checkpoints are not needed: migrate with a full scan.
        let output = runner
            .run_once_osv((), config.clone(), json!({"osv_http_v1": "0".repeat(64)}))
            .await?;
        assert_eq!(output.report.number_of_items, 3);
        // Filter changes invalidate the checkpoint and use the same year
        // filtering as Git (published takes precedence over modified).
        let mut filtered = config;
        filtered.start_year = Some(2025);
        let output = runner
            .run_once_osv((), filtered, output.continuation.unwrap())
            .await?;
        assert_eq!(output.report.number_of_items, 3);
        assert!(output.report.messages.is_empty());
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[tokio::test]
    async fn records_published_during_scan_are_fetched_next_time(
        ctx: &TrustifyContext,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let published = Arc::new(Mutex::new(None));
        let timestamp = published.clone();
        Mock::given(path("/all.json"))
            .respond_with(move |_: &Request| {
                // Published after the scan starts, but not yet in this index.
                *timestamp.lock() = Some(Utc::now());
                ResponseTemplate::new(200).set_body_json(json!([]))
            })
            .mount(&server)
            .await;
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        let output = runner.run_once_osv((), config.clone(), Value::Null).await?;
        let token = output.continuation.unwrap();
        let modified = published.lock().unwrap();
        assert!(from_value::<Continuation>(token.clone())?.osv_http_v2 <= modified);
        serve(&server, &[("OSV-2026-0001", &modified.to_rfc3339())], None).await;
        let output = runner.run_once_osv((), config, token).await?;
        assert_eq!(output.report.number_of_items, 1);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[tokio::test]
    async fn records_updated_during_scan_allow_watermark_progress(
        ctx: &TrustifyContext,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let id = "OSV-2026-0001";
        serve(&server, &[(id, "2026-01-01T00:00:00Z")], None).await;
        let updated = Arc::new(Mutex::new(None));
        let timestamp = updated.clone();
        Mock::given(path(format!("/{id}.json")))
            .respond_with(move |_: &Request| {
                let modified = Utc::now();
                *timestamp.lock() = Some(modified);
                ResponseTemplate::new(200).set_body_json(json!({
                    "schema_version": "1.7.5", "id": id, "modified": modified,
                    "summary": "updated during scan"
                }))
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        let output = runner.run_once_osv((), config.clone(), Value::Null).await?;
        assert_eq!(output.report.number_of_items, 1);
        let token = output.continuation.unwrap();
        let modified = updated.lock().unwrap();
        assert!(from_value::<Continuation>(token.clone())?.osv_http_v2 <= modified);

        // The refreshed index still selects this record on the next run.
        serve(&server, &[(id, &modified.to_rfc3339())], None).await;
        let output = runner.run_once_osv((), config.clone(), token).await?;
        assert_eq!(output.report.number_of_items, 1);
        let token = output.continuation.unwrap();
        assert!(from_value::<Continuation>(token.clone())?.osv_http_v2 > modified);
        let output = runner.run_once_osv((), config, token).await?;
        assert_eq!(output.report.number_of_items, 0);
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|request| request.url.path() != "/all.json")
                .count(),
            1
        );
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[rstest]
    #[case::older_document("OSV-2026-0001", true)]
    #[case::wrong_id("OSV-2026-0002", false)]
    #[tokio::test]
    async fn inconsistent_records_preserve_watermark(
        ctx: &TrustifyContext,
        #[case] document_id: &str,
        #[case] older: bool,
        #[values(false, true)] incremental: bool,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        let token = if incremental {
            serve(&server, &[], None).await;
            runner
                .run_once_osv((), config.clone(), Value::Null)
                .await?
                .continuation
                .unwrap()
        } else {
            Value::Null
        };
        let modified = Utc::now();
        let document_modified = if older {
            modified - TimeDelta::seconds(1)
        } else {
            modified
        };
        let id = "OSV-2026-0001";
        serve(&server, &[(id, &modified.to_rfc3339())], None).await;
        Mock::given(path(format!("/{id}.json")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "schema_version": "1.7.5", "id": document_id,
                "modified": document_modified, "summary": "inconsistent record"
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        let (output, result) = runner
            .run_once_osv((), config, token.clone())
            .await
            .split()?;
        assert!(result.is_err());
        assert_eq!(output.report.number_of_items, 0);
        assert!(!output.report.messages.is_empty());
        assert_eq!(output.continuation, Some(token));
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[rstest]
    #[case::not_an_array(json!({"not": "an array"}))]
    #[case::invalid_timestamp(json!([{"id": "OSV-test", "modified": "not a date"}]))]
    #[case::invalid_id(json!([{"id": "../escape", "modified": "2026-01-01T00:00:00Z"}]))]
    #[case::duplicate_ids(json!([
        {"id": "OSV-test", "modified": "2026-01-01T00:00:00Z"},
        {"id": "OSV-test", "modified": "2026-01-01T00:00:00Z"}
    ]))]
    #[tokio::test]
    async fn malformed_indexes_fail_without_fetching_records(
        ctx: &TrustifyContext,
        #[case] index: Value,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let runner = runner(ctx);
        Mock::given(path("/all.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(index))
            .mount(&server)
            .await;
        assert!(
            runner
                .run_once_osv(
                    (),
                    importer(&format!("{}/all.json", server.uri())),
                    Value::Null
                )
                .await
                .is_err()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        Ok(())
    }

    #[derive(Debug)]
    struct PendingCheckContext {
        lock: Arc<tokio::sync::Mutex<()>>,
        checks: Arc<AtomicUsize>,
    }

    impl RunContext for PendingCheckContext {
        fn name(&self) -> &str {
            "pending-check-test"
        }

        async fn is_canceled(&self) -> bool {
            let _guard = self.lock.lock().await;
            if self.checks.fetch_add(1, Ordering::SeqCst) == 1 {
                // Model a production check awaiting the database while holding
                // its mutex. Only dropping this future releases the lock.
                std::future::pending::<()>().await;
            }
            false
        }
    }

    #[test_context(TrustifyContext)]
    #[rstest]
    #[tokio::test]
    async fn pending_cancellation_check_releases_mutex(
        ctx: &TrustifyContext,
        #[values(false, true)] with_record: bool,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let entries = if with_record {
            vec![("OSV-2026-0001", "2026-01-01T00:00:00Z")]
        } else {
            vec![]
        };
        serve(&server, &entries, None).await;
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let checks = Arc::new(AtomicUsize::new(0));
        let context = PendingCheckContext {
            lock: lock.clone(),
            checks: checks.clone(),
        };
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        let output = timeout(
            Duration::from_secs(4),
            runner.run_once_osv(context, config, Value::Null),
        )
        .await??;
        assert_eq!(output.report.number_of_items, entries.len());
        assert!(output.continuation.is_some_and(|token| !token.is_null()));
        assert!(checks.load(Ordering::SeqCst) >= 3);
        assert!(lock.try_lock().is_ok());
        Ok(())
    }

    #[derive(Debug)]
    struct CancelContext(Arc<AtomicBool>);

    impl RunContext for CancelContext {
        fn name(&self) -> &str {
            "cancel-test"
        }
        async fn is_canceled(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test_context(TrustifyContext)]
    #[tokio::test]
    async fn cancellation_interrupts_download_and_preserves_retry(
        ctx: &TrustifyContext,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        serve(&server, &[], None).await;
        let token = runner
            .run_once_osv((), config.clone(), Value::Null)
            .await?
            .continuation
            .unwrap();
        let modified = Utc::now().to_rfc3339();
        let entries = [("OSV-2026-0001", modified.as_str())];
        serve(&server, &entries, None).await;
        let canceled = Arc::new(AtomicBool::new(false));
        let flag = canceled.clone();
        Mock::given(path(format!("/{}.json", entries[0].0)))
            .respond_with(move |_: &Request| {
                flag.store(true, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_string("{}")
                    .set_delay(Duration::from_secs(10))
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let result = timeout(
            Duration::from_secs(4),
            runner.run_once_osv(CancelContext(canceled), config.clone(), token.clone()),
        )
        .await?;
        let (output, result) = result.split()?;
        assert!(result.unwrap_err().to_string().contains("canceled"));
        assert_eq!(output.report.number_of_items, 0);
        assert_eq!(output.continuation.as_ref(), Some(&token));
        serve(&server, &entries, None).await;
        let output = runner
            .run_once_osv((), config, output.continuation.unwrap())
            .await?;
        assert_eq!(output.report.number_of_items, 1);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[tokio::test(flavor = "multi_thread")]
    async fn git_import_still_uses_shared_processing(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let repo = Repository::init(directory.path())?;
        write(
            directory.path().join("advisory.json"),
            to_vec(&json!({
                "id": "OSV-2026-0001", "modified": "2026-01-01T00:00:00Z", "summary": "Git advisory"
            }))?,
        )?;
        let mut index = repo.index()?;
        index.add_path(Path::new("advisory.json"))?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let signature = Signature::now("test", "test@example.org")?;
        repo.commit(Some("HEAD"), &signature, &signature, "test", &tree, &[])?;
        let runner = runner(ctx);
        let source = directory.path().to_str().unwrap();
        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let context = || Context {
            context: (),
            source: source.to_string(),
            labels: Default::default(),
            years: Default::default(),
            start_year: None,
            report: report.clone(),
            ingestor: IngestorService::new(Graph::new(), runner.storage.clone(), None),
            db: runner.db.clone(),
        };
        // Local Git transport cannot do shallow clones. Disable depth only
        // for this fixture, using the same handler and processor as the runner.
        let continuation = GitWalker::new(source, OsvHandler(context()))
            .depth(0)
            .working_dir(directory.path().join("checkout"))
            .run()
            .await?;
        assert_eq!(report.lock().clone().build().number_of_items, 1);
        assert!(report.lock().clone().build().messages.is_empty());
        assert!(to_value(continuation)?.is_string());
        Ok(())
    }
}
