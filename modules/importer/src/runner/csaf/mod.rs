mod report;
pub mod storage;

use crate::{
    model::CsafImporter,
    runner::{
        RunOutput,
        common::{filter::Filter, validation},
        context::RunContext,
        csaf::report::CsafReportVisitor,
        report::{ReportBuilder, ReportVisitor, ScannerError},
    },
    server::context::WalkerProgress,
};
use csaf_walker::{
    metadata::MetadataRetriever,
    retrieve::RetrievingVisitor,
    source::{HttpOptions, HttpSource},
    validation::ValidationVisitor,
    walker::Walker,
};
use parking_lot::Mutex;
use reqwest::StatusCode;
use std::collections::HashSet;
use std::{sync::Arc, time::SystemTime};
use tracing::instrument;
use trustify_module_ingestor::{graph::Graph, service::IngestorService};
use url::Url;
use walker_common::fetcher::{Fetcher, FetcherOptions};

impl super::ImportRunner {
    #[instrument(skip_all, err)]
    pub async fn run_once_csaf(
        &self,
        context: impl RunContext,
        importer: CsafImporter,
        last_success: Option<SystemTime>,
    ) -> Result<RunOutput, ScannerError> {
        // progress reporting

        let progress = context.progress(format!("Import CSAF: {}", importer.source));

        // report

        let CsafImporter {
            common,
            source,
            v3_signatures,
            only_patterns,
            fetch_retries,
            ignore_missing,
        } = importer;

        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let fetcher =
            Fetcher::new(FetcherOptions::new().retries(fetch_retries.unwrap_or_default())).await?;
        let options = HttpOptions::new().since(last_success);

        let source = match Url::parse(&source) {
            Ok(url) => HttpSource::new(url, fetcher, options),
            Err(_) => HttpSource::new(MetadataRetriever::new(source.clone()), fetcher, options),
        };

        // storage (called by validator)
        let ingestor = IngestorService::new(
            Graph::new(self.db.clone()),
            self.storage.clone(),
            self.analysis.clone(),
        );

        let storage = storage::StorageVisitor {
            context,
            ingestor,
            db: self.db.clone(),
            labels: common.labels,
            report: report.clone(),
        };

        // wrap storage with report

        let storage = CsafReportVisitor {
            next: ReportVisitor::new(report.clone(), storage),
            ignore_errors: match ignore_missing {
                true => HashSet::from_iter([StatusCode::NOT_FOUND]),
                false => HashSet::new(),
            },
        };

        // validate (called by retriever)

        let options = validation::options(v3_signatures)?;
        let validation = ValidationVisitor::new(storage).with_options(options);

        // retriever (called by filter)

        let visitor = RetrievingVisitor::new(source.clone(), validation);

        // filter

        let filter = Filter::from_config(visitor, only_patterns)?;

        // walker

        Walker::new(source)
            .with_progress(WalkerProgress(progress))
            .walk(filter)
            .await
            // if the walker fails, we record the outcome as part of the report, but skip any
            // further processing, like storing the marker
            .map_err(|err| ScannerError::Normal {
                err: err.into(),
                output: RunOutput {
                    report: report.lock().clone().build(),
                    continuation: None,
                },
            })?;

        Ok(match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().clone(),
        }
        .build()
        .into())
    }
}
