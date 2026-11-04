mod handler;
mod http;

use crate::{
    model::{OsvImporter, OsvTransport},
    runner::{
        RunOutput,
        common::walker::{CallbackError, Callbacks, GitWalker},
        context::RunContext,
        report::{Phase, ReportBuilder, ScannerError},
    },
};
use chrono::Datelike;
use handler::OsvHandler;
use parking_lot::Mutex;
use serde_json::{Value, from_value, to_value};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::runtime::Handle;
use tracing::instrument;
use trustify_common::db::ReadWrite;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::Cache;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Format, IngestorService, advisory::osv::parse},
};

struct Context<C: RunContext + 'static> {
    context: C,
    source: String,
    labels: Labels,
    years: HashSet<u16>,
    start_year: Option<u16>,
    report: Arc<Mutex<ReportBuilder>>,
    ingestor: IngestorService,
    db: ReadWrite,
}

impl<C: RunContext> Context<C> {
    async fn store(&self, file: &str, data: &[u8]) -> anyhow::Result<()> {
        self.report.lock().tick();

        // apply year based filter, we need to parse
        if !self.years.is_empty() || self.start_year.is_some() {
            let osv = parse(data)?;

            let year = osv
                .published
                .unwrap_or(osv.modified)
                .year()
                .clamp(u16::MIN as _, u16::MAX as _) as u16;

            // check the set of years
            if !self.years.is_empty() && !self.years.contains(&year) {
                return Ok(());
            }

            // check starting year
            if let Some(start_year) = self.start_year
                && year < start_year
            {
                return Ok(());
            }
        }

        self.db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(
                        data,
                        Format::OSV,
                        Labels::new()
                            .add("source", &self.source)
                            .add("importer", self.context.name())
                            .add("file", file)
                            .extend(self.labels.0.clone()),
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await?;

        Ok(())
    }
}

impl<C: RunContext> Callbacks<Vec<u8>> for Context<C> {
    fn loading_error(&self, path: PathBuf, message: String) {
        self.report
            .lock()
            .add_error(Phase::Validation, path.to_string_lossy(), message);
    }

    fn process(&self, path: &Path, osv: Vec<u8>) -> Result<(), CallbackError> {
        if let Err(err) = Handle::current().block_on(self.store(&path.to_string_lossy(), &osv)) {
            self.report
                .lock()
                .add_error(Phase::Upload, path.to_string_lossy(), err.to_string());
        }

        self.context.check_canceled_sync(|| CallbackError::Canceled)
    }

    fn is_canceled(&self) -> bool {
        self.context.is_canceled_sync()
    }
}

impl super::ImportRunner {
    #[instrument(skip(self, context), err)]
    pub async fn run_once_osv(
        &self,
        context: impl RunContext + 'static,
        osv: OsvImporter,
        continuation: Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor =
            IngestorService::new(Graph::new(), self.storage.clone(), self.analysis.clone());

        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        // progress reporting

        let progress = context.progress(format!("Import OSV: {}", osv.source));

        // run the walker

        let shared = Context {
            context,
            source: osv.source.clone(),
            labels: osv.common.labels,
            years: osv.years,
            start_year: osv.start_year,
            report: report.clone(),
            ingestor,
            db: self.db.clone(),
        };

        let (continuation, error) = match osv.transport {
            OsvTransport::Http { base_url } => {
                let (index, base) = http::feed_urls(&osv.source, base_url.as_ref())?;
                http::HttpWalker::new(shared, index, base, continuation)?
                    .run()
                    .await?
            }
            OsvTransport::Git { branch, path } => {
                let working_dir = self.create_working_dir("osv", &osv.source).await?;
                let walker = GitWalker::new(osv.source, OsvHandler(shared))
                    .continuation(from_value(continuation).unwrap_or_default())
                    .branch(branch)
                    .path(path)
                    .progress(progress);

                let continuation = match working_dir {
                    Some(working_dir) => walker.working_dir(working_dir).run().await,
                    None => walker.run().await,
                }
                .map_err(|err| ScannerError::Critical(err.into()))?;
                (to_value(continuation).ok(), None)
            }
        };

        // extract the report

        let report = match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build();

        // return

        let output = RunOutput {
            report,
            continuation,
        };
        match error {
            Some(err) => Err(ScannerError::Normal {
                err,
                output: Box::new(output),
            }),
            None => Ok(output),
        }
    }
}
