//! OSV.dev's REST-source convention: an index of id/modified pairs and
//! individual OSV records at <base>/<id>.json.
use super::Context;
use crate::{
    model::{OsvImporter, OsvTransport},
    runner::{
        context::RunContext,
        progress::{Progress, ProgressInstance},
        report::Phase,
    },
};
use anyhow::{Context as _, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt, stream};
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    time::Duration,
};
use trustify_common::reqwest::ClientFactory;
use trustify_module_ingestor::service::advisory::osv::parse;
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};
use url::Url;
use walker_common::fetcher::{DataProcessor, Fetcher};

const INDEX_LIMIT: usize = 256 * 1024 * 1024;
const RECORD_LIMIT: usize = 16 * 1024 * 1024;
const CONCURRENCY: usize = 8;

pub(super) fn feed_urls(osv: &OsvImporter) -> anyhow::Result<Option<(Url, Url)>> {
    let source = Url::parse(&osv.source).ok();
    let http = match osv.transport {
        Some(OsvTransport::Http) => true,
        Some(OsvTransport::Git) => false,
        None => source.as_ref().is_some_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.path_segments().and_then(|mut parts| parts.next_back()) == Some("all.json")
        }),
    };
    if !http {
        ensure!(osv.base_url.is_none(), "OSV baseUrl requires an HTTP feed");
        return Ok(None);
    }
    ensure!(
        osv.branch.is_none() && osv.path.is_none(),
        "OSV branch and path are Git-only options"
    );
    let source = source.context("invalid OSV HTTP index URL")?;
    ensure_http(&source)?;
    let mut base = osv.base_url.clone().unwrap_or(source.join("./")?);
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
    Ok(Some((source, base)))
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

/// The potentially large map is a content-addressed blob, not part of the
/// importer's database row. Missing blobs safely cause a full re-scan.
#[derive(Default, Serialize, Deserialize)]
struct Checkpoint {
    source: String,
    base: String,
    years: Vec<u16>,
    start_year: Option<u16>,
    labels: Value,
    records: BTreeMap<String, DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
struct Continuation {
    osv_http_v1: String,
}

async fn load_checkpoint(
    storage: &DispatchBackend,
    continuation: Value,
) -> anyhow::Result<Checkpoint> {
    let Ok(token) = serde_json::from_value::<Continuation>(continuation) else {
        return Ok(Checkpoint::default());
    };
    ensure!(
        token.osv_http_v1.len() == 64 && token.osv_http_v1.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid OSV checkpoint key"
    );
    let Some(stream) = storage
        .retrieve(StorageKey::from_sha256(&token.osv_http_v1))
        .await?
    else {
        return Ok(Checkpoint::default());
    };
    let bytes = stream
        .try_fold(Vec::new(), |mut bytes, chunk| async move {
            ensure!(
                chunk.len() <= INDEX_LIMIT.saturating_sub(bytes.len()),
                "OSV checkpoint exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
            Ok::<_, anyhow::Error>(bytes)
        })
        .await?;
    Ok(serde_json::from_slice(&bytes)?)
}

struct HttpFetcher {
    fetcher: Fetcher,
    index: Url,
    base: Url,
}

impl HttpFetcher {
    fn new(index: Url, base: Url) -> anyhow::Result<Self> {
        Ok(Self {
            // Use the shared TLS trust setup (including the OpenShift service
            // CA), walker user agent, and Fetcher's retry/rate-limit policy.
            fetcher: Fetcher::from(
                ClientFactory::new()
                    .new_builder()?
                    .user_agent(walker_common::USER_AGENT)
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(30))
                    .build()?,
            ),
            index,
            base,
        })
    }

    async fn index(&self) -> anyhow::Result<Vec<Entry>> {
        serde_json::from_slice(&self.fetch(&self.index, INDEX_LIMIT).await?)
            .context("invalid OSV REST index")
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
    storage: DispatchBackend,
    fetcher: HttpFetcher,
    state: Checkpoint,
}

impl<C: RunContext> HttpWalker<C> {
    pub(super) async fn new(
        context: Context<C>,
        storage: DispatchBackend,
        index: Url,
        base: Url,
        continuation: Value,
    ) -> anyhow::Result<Self> {
        let state = load_checkpoint(&storage, continuation).await?;
        Ok(Self {
            context,
            storage,
            fetcher: HttpFetcher::new(index, base)?,
            state,
        })
    }

    pub(super) async fn run(self) -> anyhow::Result<(Option<Value>, Option<anyhow::Error>)> {
        let Self {
            context,
            storage,
            fetcher,
            mut state,
        } = self;
        let index = &fetcher.index;
        let base = &fetcher.base;
        let mut years: Vec<_> = context.years.iter().copied().collect();
        years.sort_unstable();
        let labels = serde_json::to_value(&context.labels)?;
        if state.source != index.as_str()
            || state.base != base.as_str()
            || state.years != years
            || state.start_year != context.start_year
            || state.labels != labels
        {
            state = Checkpoint {
                source: index.to_string(),
                base: base.to_string(),
                years,
                start_year: context.start_year,
                labels,
                records: BTreeMap::new(),
            };
        }
        context
            .context
            .check_canceled(|| anyhow!("OSV import canceled"))
            .await?;
        let canceled = async {
            loop {
                if context.context.is_canceled().await {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };
        tokio::pin!(canceled);
        let entries = tokio::select! {
            entries = fetcher.index() => entries?,
            () = &mut canceled => bail!("OSV import canceled"),
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
            .filter(|entry| state.records.get(&entry.id) != Some(&entry.modified))
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
            let result = tokio::select! {
                result = downloads.next() => match result {
                    Some(result) => result,
                    None => break,
                },
                () = &mut canceled => {
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
                            document.modified == entry.modified,
                            "OSV record changed since index was fetched"
                        );
                        context.store(url.as_str(), &data).await
                    }
                    .await;
                    (Phase::Upload, result)
                }
                Err(err) => (Phase::Retrieval, Err(err)),
            };
            match result {
                Ok(()) => {
                    state.records.insert(entry.id.clone(), entry.modified);
                }
                Err(err) => {
                    context
                        .report
                        .lock()
                        .add_error(phase, url.as_str(), err.to_string());
                    error = Some(anyhow!("some OSV records failed; see import report"));
                }
            }
            progress.tick().await;
        }
        drop(downloads);
        progress.finish().await;
        // Absence from an index is not an OSV withdrawal. Keep existing advisories,
        // but forget checkpoints so a reappearing ID is fetched again.
        state.records.retain(|id, _| seen.contains(id.as_str()));
        let bytes = serde_json::to_vec(&state)?;
        let stored = storage
            .store(bytes.as_slice())
            .await
            .map_err(|err| anyhow!("failed to store OSV checkpoint: {err}"))?;
        let continuation = serde_json::to_value(Continuation {
            osv_http_v1: stored.key().to_string(),
        })?;
        Ok((Some(continuation), error))
    }
}

#[cfg(test)]
mod tests {
    use super::super::handler::OsvHandler;
    use super::*;
    use crate::{
        model::auth::CredentialConfig,
        runner::{
            ImportRunner,
            common::walker::GitWalker,
            report::{ReportBuilder, SplitScannerError},
        },
    };
    use git2::{Repository, Signature};
    use parking_lot::Mutex;
    use serde_json::json;
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use test_context::test_context;
    use trustify_common::db::ReadWrite;
    use trustify_module_ingestor::{graph::Graph, service::IngestorService};
    use trustify_test_context::TrustifyContext;
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn importer(source: &str) -> OsvImporter {
        serde_json::from_value(json!({"source": source, "period": "1h"})).unwrap()
    }

    #[test]
    fn routing() {
        for source in [
            "https://example.com/osv/all.json",
            "http://localhost/all.json?token=secret",
        ] {
            assert!(feed_urls(&importer(source)).unwrap().is_some());
        }
        for source in [
            "https://github.com/org/repo",
            "https://github.com/org/repo.git",
            "git@example.com:org/repo",
            "/local/repo",
        ] {
            assert!(feed_urls(&importer(source)).unwrap().is_none());
        }
        let mut config = importer("https://example.com/index");
        config.transport = Some(OsvTransport::Http);
        config.base_url = Some(Url::parse("https://records.example.com/osv").unwrap());
        let (_, base) = feed_urls(&config).unwrap().unwrap();
        assert_eq!(
            record_url(&base, "CGA-1234").unwrap().as_str(),
            "https://records.example.com/osv/CGA-1234.json"
        );
        config.branch = Some("main".into());
        assert!(feed_urls(&config).is_err());
        config.branch = None;
        config.source = "file:///all.json".into();
        assert!(feed_urls(&config).is_err());
        config = importer("https://example.com/all.json");
        config.transport = Some(OsvTransport::Git);
        assert!(feed_urls(&config).unwrap().is_none());
    }

    #[test]
    fn untrusted_ids_cannot_escape_base() {
        let base = Url::parse("https://example.com/osv/").unwrap();
        for id in [
            "",
            "../escape",
            "https://evil.test/",
            "//evil.test",
            "a?b",
            "a#b",
            "a%2fb",
            "a\\b",
        ] {
            assert!(record_url(&base, id).is_err(), "{id}");
        }
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
            .and(header("user-agent", walker_common::USER_AGENT))
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
            .and(header("user-agent", walker_common::USER_AGENT))
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
                .and(header("user-agent", walker_common::USER_AGENT))
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
        let first = [("CGA-2222-2222-2222", "2026-01-01T00:00:00Z")];
        serve(&server, &first, None).await;
        let output = runner.run_once_osv((), config.clone(), Value::Null).await?;
        assert_eq!(output.report.number_of_items, 1);
        let token = output.continuation.unwrap();
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
        let next = [
            (first[0].0, "2026-02-01T00:00:00Z"),
            ("CGA-3333-3333-3333", "2020-01-01T00:00:00Z"),
            ("CGA-4444-4444-4444", "2026-02-01T00:00:00Z"),
        ];
        serve(&server, &next, Some(next[2].0)).await;
        let (output, result) = runner
            .run_once_osv((), config.clone(), token)
            .await
            .split()?;
        assert!(result.is_err());
        assert_eq!(output.report.number_of_items, 2);
        let token = output.continuation.unwrap();
        serve(&server, &next, None).await;
        let output = runner.run_once_osv((), config.clone(), token).await?;
        assert_eq!(output.report.number_of_items, 1);
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
        // A missing checkpoint falls back to a full scan.
        let token = output.continuation.unwrap();
        let key = serde_json::from_value::<Continuation>(token.clone())?.osv_http_v1;
        runner.storage.delete(StorageKey::from_sha256(&key)).await?;
        let output = runner.run_once_osv((), config.clone(), token).await?;
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
    async fn malformed_indexes_fail_without_fetching_records(
        ctx: &TrustifyContext,
    ) -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let runner = runner(ctx);
        for index in [
            json!({"not": "an array"}),
            json!([{"id": "CGA-test", "modified": "not a date"}]),
            json!([{"id": "../escape", "modified": "2026-01-01T00:00:00Z"}]),
            json!([
                {"id": "CGA-test", "modified": "2026-01-01T00:00:00Z"},
                {"id": "CGA-test", "modified": "2026-01-01T00:00:00Z"}
            ]),
        ] {
            server.reset().await;
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
        }
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
        let entries = [("CGA-2222-2222-2222", "2026-01-01T00:00:00Z")];
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
        let runner = runner(ctx);
        let config = importer(&format!("{}/all.json", server.uri()));
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            runner.run_once_osv(CancelContext(canceled), config.clone(), Value::Null),
        )
        .await?;
        let (output, result) = result.split()?;
        assert!(result.unwrap_err().to_string().contains("canceled"));
        assert_eq!(output.report.number_of_items, 0);
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
        std::fs::write(
            directory.path().join("advisory.json"),
            serde_json::to_vec(&json!({
                "id": "CGA-2222-2222-2222", "modified": "2026-01-01T00:00:00Z", "summary": "Git advisory"
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
        assert!(serde_json::to_value(continuation)?.is_string());
        Ok(())
    }
}
