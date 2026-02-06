use crate::runner::common::Error;
use crate::runner::report::{Phase, ReportBuilder};
use std::io::{Cursor, Read};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::bytes::Buf;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};
use zip::ZipArchive;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct LastModified(Option<String>);

pub struct CweWalker {
    continuation: LastModified,
    source: String,
    ingestor: IngestorService,
    db: Database,
    report: Arc<Mutex<ReportBuilder>>,
}

impl CweWalker {
    pub fn new(
        source: impl Into<String>,
        ingestor: IngestorService,
        db: Database,
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
    #[instrument(skip(self), ret)]
    pub async fn run(self) -> Result<LastModified, Error> {
        let response = reqwest::get(&self.source).await?;

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

        let body = response.bytes().await?;

        let content = if self.source.ends_with(".zip") {
            let mut bytes = Vec::new();
            body.reader().read_to_end(&mut bytes)?;
            let read = Cursor::new(bytes);
            let mut archive = ZipArchive::new(read)?;
            let mut entry = archive.by_index(0)?;
            let mut tmp = Vec::new();
            entry.read_to_end(&mut tmp)?;
            tmp
        } else {
            body.into()
        };

        let result = self
            .db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(
                        &content,
                        Format::CweCatalog,
                        Labels::new()
                            .add("source", &self.source)
                            .add("importer", "CWE Catalog"),
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
