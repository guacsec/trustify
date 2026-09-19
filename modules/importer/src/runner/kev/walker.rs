use crate::runner::{
    common::Error,
    report::{Message, Phase, ReportBuilder},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_common::db::ReadWrite;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService, kev::LABEL_CATALOG};

/// Maximum size of the downloaded catalog, guarding against oversized
/// responses. The CISA KEV catalog is a few MB of JSON today and grows
/// slowly, so 64 MiB leaves plenty of headroom.
const CATALOG_SIZE_LIMIT: usize = 64 * 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-read, not per-transfer, so a slow but progressing download survives while
/// a silent connection still fails fast. Without it a stalled host blocks the run
/// forever: heartbeats keep flowing, so the stale-job reaper never reaps it.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Continuation token carrying the `Last-Modified` header of the previously
/// processed catalog download.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<String>);

/// Downloads a KEV catalog document and hands it to the ingestor.
pub struct KevWalker {
    continuation: LastModified,
    source: String,
    catalog: Option<String>,
    connect_timeout: Duration,
    read_timeout: Duration,
    ingestor: IngestorService,
    db: ReadWrite,
    report: Arc<Mutex<ReportBuilder>>,
}

impl KevWalker {
    /// Create a new walker downloading from `source`, storing entries under
    /// the `catalog` source identifier (the ingestor's default if `None`).
    pub fn new(
        source: impl Into<String>,
        catalog: Option<String>,
        ingestor: IngestorService,
        db: ReadWrite,
        report: Arc<Mutex<ReportBuilder>>,
    ) -> Self {
        Self {
            continuation: LastModified(None),
            source: source.into(),
            catalog,
            connect_timeout: CONNECT_TIMEOUT,
            read_timeout: READ_TIMEOUT,
            ingestor,
            db,
            report,
        }
    }

    /// Set a continuation token from a previous run.
    pub fn continuation(mut self, continuation: LastModified) -> Self {
        self.continuation = continuation;
        self
    }

    /// Override the default download timeouts, to keep the test for them fast.
    #[cfg(test)]
    pub fn timeouts(mut self, connect: Duration, read: Duration) -> Self {
        self.connect_timeout = connect;
        self.read_timeout = read;
        self
    }

    /// Run the walker
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn run(self) -> Result<LastModified, Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .read_timeout(self.read_timeout)
            .build()?;

        let mut response = client.get(&self.source).send().await?.error_for_status()?;

        let last_modified = response
            .headers()
            .get("Last-Modified")
            .map(|inner| inner.to_str())
            .transpose()?
            .map(|inner| inner.to_string());

        match (&self.continuation.0, &last_modified) {
            (Some(cont), Some(last_mod)) if cont.eq(last_mod) => {
                // no change, just keep the same continuation
                return Ok(self.continuation);
            }
            _ => {
                // fall-through, process, return new last-modified as continuation
            }
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > CATALOG_SIZE_LIMIT {
                return Err(Error::Processing(anyhow::anyhow!(
                    "catalog from {} exceeds the size limit of {CATALOG_SIZE_LIMIT} bytes",
                    self.source
                )));
            }
            body.extend_from_slice(&chunk);
        }

        let mut labels = Labels::new()
            .add("source", &self.source)
            .add("importer", "CISA KEV Catalog");
        if let Some(catalog) = &self.catalog {
            labels = labels.add(LABEL_CATALOG, catalog);
        }

        let result = self
            .db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(&body, Format::CisaKev, labels, None, Cache::Skip, tx)
                    .await
            })
            .await;

        let ingested = {
            let mut report = self.report.lock().await;
            match result {
                Ok(result) => {
                    report.tick();
                    // surface the loader's warnings, e.g. dropped catalog dates
                    report.extend_messages(
                        Phase::Upload,
                        self.source.clone(),
                        result.warnings.iter().map(Message::warning),
                    );
                    true
                }
                Err(err) => {
                    report.add_error(Phase::Upload, self.source.clone(), err.to_string());
                    false
                }
            }
        };

        if !ingested {
            // had an error, keep the old continuation as active.
            return Ok(self.continuation);
        }

        Ok(LastModified(last_modified))
    }
}
