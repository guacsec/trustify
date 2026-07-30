use crate::runner::{
    common::Error,
    report::{Phase, ReportBuilder},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_common::db::ReadWrite;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};

/// Maximum size of the downloaded catalog, guarding against oversized
/// responses. The CISA KEV catalog is a few MB of JSON today and grows
/// slowly, so 64 MiB leaves plenty of headroom.
const CATALOG_SIZE_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<String>);

pub struct KevWalker {
    continuation: LastModified,
    source: String,
    ingestor: IngestorService,
    db: ReadWrite,
    report: Arc<Mutex<ReportBuilder>>,
}

impl KevWalker {
    pub fn new(
        source: impl Into<String>,
        ingestor: IngestorService,
        db: ReadWrite,
        report: Arc<Mutex<ReportBuilder>>,
    ) -> Self {
        Self {
            continuation: LastModified(None),
            source: source.into(),
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

    /// Run the walker
    #[instrument(skip(self), err(level=tracing::Level::INFO))]
    pub async fn run(self) -> Result<LastModified, Error> {
        let mut response = reqwest::get(&self.source).await?.error_for_status()?;

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

        let result = self
            .db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(
                        &body,
                        Format::CisaKev,
                        Labels::new()
                            .add("source", &self.source)
                            .add("importer", "CISA KEV Catalog"),
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await;

        if let Err(err) = result {
            self.report
                .lock()
                .await
                .add_error(Phase::Upload, self.source, err.to_string());

            // had an error, keep the old continuation as active.
            return Ok(self.continuation);
        }

        Ok(LastModified(last_modified))
    }
}
