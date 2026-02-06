mod walker;

use crate::model::ClearlyDefinedImporter;
use crate::runner::clearly_defined::walker::ClearlyDefinedWalker;
use crate::runner::context::RunContext;
use crate::runner::report::{ReportBuilder, ScannerError};
use crate::server::RunOutput;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::IngestorService;

impl super::ImportRunner {
    #[instrument(skip(self), ret)]
    pub async fn run_once_clearly_defined(
        &self,
        context: impl RunContext + 'static,
        clearly_defined: ClearlyDefinedImporter,
        continuation: serde_json::Value,
    ) -> Result<RunOutput, ScannerError> {
        let ingestor = IngestorService::new(
            Graph::new(self.db.clone()),
            self.storage.clone(),
            self.analysis.clone(),
        );

        let report = Arc::new(Mutex::new(ReportBuilder::new()));
        let continuation = serde_json::from_value(continuation).unwrap_or_default();

        let progress = context.progress(format!(
            "Import ClearlyDefined curation: {}",
            clearly_defined.source
        ));

        let walker = ClearlyDefinedWalker::new(
            clearly_defined.source.clone(),
            ingestor,
            self.db.clone(),
            report.clone(),
            progress,
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
