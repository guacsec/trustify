mod handler;

use crate::{
    model::CveImporter,
    runner::{
        RunOutput,
        common::walker::{CallbackError, Callbacks, GitWalker},
        context::RunContext,
        report::{Phase, ReportBuilder, ScannerError},
    },
};
use handler::CveHandler;
use parking_lot::Mutex;
use std::{path::Path, path::PathBuf, sync::Arc};
use tokio::runtime::Handle;
use tracing::instrument;
use trustify_common::db::Database;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::Cache;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Format, IngestorService},
};

struct Context<C: RunContext + 'static> {
    context: C,
    source: String,
    labels: Labels,
    report: Arc<Mutex<ReportBuilder>>,
    ingestor: IngestorService,
    db: Database,
}

impl<C: RunContext> Context<C> {
    fn store(&self, path: &Path, data: Vec<u8>) -> anyhow::Result<()> {
        self.report.lock().tick();

        Handle::current().block_on(async {
            self.db
                .transaction(async |tx| {
                    self.ingestor
                        .ingest(
                            &data,
                            Format::CVE,
                            Labels::new()
                                .add("source", &self.source)
                                .add("importer", self.context.name())
                                .add("file", path.to_string_lossy())
                                .extend(self.labels.0.clone()),
                            None,
                            Cache::Skip,
                            tx,
                        )
                        .await
                })
                .await
        })?;

        Ok(())
    }
}

impl<C: RunContext> Callbacks<Vec<u8>> for Context<C> {
    fn loading_error(&self, path: PathBuf, message: String) {
        self.report
            .lock()
            .add_error(Phase::Validation, path.to_string_lossy(), message);
    }

    fn process(&self, path: &Path, cve: Vec<u8>) -> Result<(), CallbackError> {
        if let Err(err) = self.store(path, cve) {
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
    pub async fn run_once_cve(
        &self,
        context: impl RunContext + 'static,
        cve: CveImporter,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor = IngestorService::new(
            Graph::new(self.db.clone()),
            self.storage.clone(),
            self.analysis.clone(),
        );

        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let continuation = serde_json::from_value(continuation).unwrap_or_default();

        // working dir

        let working_dir = self.create_working_dir("cve", &cve.source).await?;

        // progress reporting

        let progress = context.progress(format!("Import CVE: {}", cve.source));

        // run the walker

        let walker = GitWalker::new(
            cve.source.clone(),
            CveHandler {
                callbacks: Context {
                    context,
                    source: cve.source,
                    labels: cve.common.labels,
                    report: report.clone(),
                    ingestor,
                    db: self.db.clone(),
                },
                years: cve.years,
                start_year: cve.start_year,
            },
        )
        .path(Some("cves"))
        .continuation(continuation)
        .progress(progress);

        let continuation = match working_dir {
            Some(working_dir) => walker.working_dir(working_dir).run().await,
            None => walker.run().await,
        }
        .map_err(|err| ScannerError::Normal {
            err: err.into(),
            output: RunOutput {
                report: report.lock().clone().build(),
                continuation: None,
            },
        })?;

        // extract the report

        let report = match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build();

        // return

        Ok(RunOutput {
            report,
            continuation: serde_json::to_value(continuation).ok(),
        })
    }
}
