mod walker;

use crate::model::CweImporter;
use crate::runner::{
    RunOutput,
    context::RunContext,
    cwe::walker::CweWalker,
    report::{ReportBuilder, ScannerError},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_module_ingestor::{graph::Graph, service::IngestorService};

impl super::ImportRunner {
    #[instrument(skip(self), ret)]
    pub async fn run_once_cwe_catalog(
        &self,
        context: impl RunContext + 'static,
        cwe_catalog: CweImporter,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor = IngestorService::new(
            Graph::new(self.db.clone()),
            self.storage.clone(),
            self.analysis.clone(),
        );

        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let continuation = serde_json::from_value(continuation).unwrap_or_default();

        // no working-dir required

        // one file, no progress to care about.

        // run the walker

        let walker = CweWalker::new(
            cwe_catalog.source.clone(),
            ingestor,
            self.db.clone(),
            report.clone(),
        )
        .continuation(continuation);

        match walker.run().await {
            Ok(continuation) => {
                // extract the report
                let report = match Arc::try_unwrap(report) {
                    Ok(report) => report.into_inner(),
                    Err(report) => report.lock().await.clone(),
                }
                .build();
                Ok(RunOutput {
                    report,
                    continuation: serde_json::to_value(continuation).ok(),
                })
            }
            Err(err) => Err(ScannerError::Normal {
                err: err.into(),
                output: RunOutput {
                    report: report.lock().await.clone().build(),
                    continuation: None,
                },
            }),
        }
    }
}
