mod report;
pub mod storage;

use crate::{
    model::SbomImporter,
    runner::{
        RunOutput,
        common::{filter::Filter, validation},
        context::RunContext,
        report::{ReportBuilder, ReportVisitor, ScannerError},
        sbom::report::SbomReportVisitor,
    },
    server::context::WalkerProgress,
};
use parking_lot::Mutex;
use reqwest::StatusCode;
use sbom_walker::{
    retrieve::RetrievingVisitor,
    source::{HttpOptions, HttpSource},
    validation::ValidationVisitor,
    walker::Walker,
};
use std::collections::HashSet;
use std::{sync::Arc, time::SystemTime};
use tracing::instrument;
use trustify_module_ingestor::{graph::Graph, service::IngestorService};
use url::Url;
use walker_common::fetcher::{Fetcher, FetcherOptions};

impl super::ImportRunner {
    #[instrument(skip_all, err)]
    pub async fn run_once_sbom(
        &self,
        context: impl RunContext,
        importer: SbomImporter,
        last_success: Option<SystemTime>,
    ) -> Result<RunOutput, ScannerError> {
        // progress

        let progress = context.progress(format!("Import SBOM: {}", importer.source));

        // report

        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let SbomImporter {
            common,
            source,
            keys,
            v3_signatures,
            only_patterns,
            size_limit,
            fetch_retries,
            ignore_missing,
        } = importer;

        let url = Url::parse(&source).map_err(|err| ScannerError::Critical(err.into()))?;

        let keys = keys.into_iter().map(|key| key.into()).collect::<Vec<_>>();
        let http_source = HttpSource::new(
            url,
            Fetcher::new(FetcherOptions::new().retries(fetch_retries.unwrap_or_default())).await?,
            HttpOptions::new().since(last_success).keys(keys),
        );

        // storage (called by validator)

        let ingestor = IngestorService::new(
            Graph::new(self.db.clone()),
            self.storage.clone(),
            self.analysis.clone(),
        );
        let storage = storage::StorageVisitor {
            context,
            source,
            labels: common.labels,
            ingestor,
            db: self.db.clone(),
            report: report.clone(),
            max_size: size_limit.map(|size| size.as_u64()),
        };

        // wrap storage with report

        let storage = SbomReportVisitor {
            next: ReportVisitor::new(report.clone(), storage),
            ignore_errors: match ignore_missing {
                true => HashSet::from_iter([StatusCode::NOT_FOUND]),
                false => HashSet::new(),
            },
        };

        // validate (called by retriever)

        //  because we might still have GPG v3 signatures
        let options = validation::options(v3_signatures)?;
        let validation = ValidationVisitor::new(storage).with_options(options);

        // retriever (called by filter)

        let visitor = RetrievingVisitor::new(http_source.clone(), validation);

        // filter

        let filter = Filter::from_config(visitor, only_patterns)?;

        // walker

        Walker::new(http_source)
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
