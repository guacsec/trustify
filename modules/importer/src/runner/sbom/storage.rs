use crate::runner::{
    common::storage::StorageError,
    context::RunContext,
    report::Severity,
    report::{Message, Phase, ReportBuilder},
};
use parking_lot::Mutex;
use sbom_walker::{
    source::HttpSource,
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext},
};
use std::sync::Arc;
use trustify_common::db::Database;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};
use walker_common::utils::url::Urlify;
use walker_common::{compression::decompress_opt, validate::ValidationError};

pub struct StorageVisitor<C: RunContext> {
    pub context: C,
    pub source: String,
    pub max_size: Option<u64>,
    pub labels: Labels,
    pub ingestor: IngestorService,
    pub db: Database,
    /// the report to report our messages to
    pub report: Arc<Mutex<ReportBuilder>>,
}

impl<C: RunContext> ValidatedVisitor<HttpSource> for StorageVisitor<C> {
    type Error = StorageError<ValidationError<HttpSource>>;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<HttpSource>>,
    ) -> Result<(), Self::Error> {
        let doc = result?;
        let file = doc.possibly_relative_url();

        if let Some(max) = self.max_size {
            let len = doc.data.len().try_into().unwrap_or(u64::MAX);
            if len > max {
                let msg =
                    format!("Skipping document due to size restriction - this: {len}, max: {max}");
                log::info!("{msg}");

                self.report
                    .lock()
                    .add_message(Phase::Upload, file, Severity::Warning, msg);

                return Ok(());
            }
        }

        let (data, _compressed) = match decompress_opt(&doc.data, doc.url.path())
            .transpose()
            .map_err(StorageError::Processing)?
        {
            Some(data) => (data, true),
            None => (doc.data.clone(), false),
        };

        let result = self
            .db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(
                        &data,
                        Format::SBOM,
                        Labels::new()
                            .add("source", &self.source)
                            .add("importer", self.context.name())
                            .add("file", &file)
                            .extend(self.labels.0.clone()),
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await
            .map_err(StorageError::Storage)?;

        self.report.lock().extend_messages(
            Phase::Upload,
            file,
            result.warnings.into_iter().map(Message::warning),
        );

        self.context.check_canceled(|| StorageError::Canceled).await
    }
}
