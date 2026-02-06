use crate::runner::{common::storage::StorageError, context::RunContext, report::ReportBuilder};
use csaf_walker::{
    source::Source,
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use parking_lot::Mutex;
use std::sync::Arc;
use trustify_common::db::Database;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Cache, Format, IngestorService};
use walker_common::utils::url::Urlify;

pub struct StorageVisitor<C: RunContext> {
    pub context: C,
    pub ingestor: IngestorService,
    pub db: Database,
    /// the report to report our messages to
    pub report: Arc<Mutex<ReportBuilder>>,
    pub labels: Labels,
}

impl<C: RunContext, S: Source> ValidatedVisitor<S> for StorageVisitor<C> {
    type Error = StorageError<ValidationError<S>>;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError<S>>,
    ) -> Result<(), Self::Error> {
        let doc = result?;
        let location = doc.context.url().to_string();
        let file = doc.possibly_relative_url();

        self.db
            .transaction(async |tx| {
                self.ingestor
                    .ingest(
                        &doc.data,
                        Format::CSAF,
                        Labels::new()
                            .add("source", &location)
                            .add("importer", self.context.name())
                            .add("file", file)
                            .extend(self.labels.0.clone()),
                        None, /* CSAF tracks issuer internally */
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await
            .map_err(StorageError::Storage)?;

        self.context.check_canceled(|| StorageError::Canceled).await
    }
}
