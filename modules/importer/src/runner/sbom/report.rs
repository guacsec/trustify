use crate::runner::{
    common::storage::StorageError,
    context::RunContext,
    report::{Phase, ReportVisitor},
    sbom::storage::StorageVisitor,
};
use reqwest::StatusCode;
use sbom_walker::{
    source::{HttpSource, HttpSourceError},
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext},
};
use std::collections::HashSet;
use trustify_module_ingestor::service;
use walker_common::{
    fetcher, retrieve::RetrievalError, utils::url::Urlify, validate::ValidationError,
};

pub struct SbomReportVisitor<C: RunContext> {
    pub next: ReportVisitor<StorageVisitor<C>>,
    pub ignore_errors: HashSet<StatusCode>,
}

impl<C: RunContext> ValidatedVisitor<HttpSource> for SbomReportVisitor<C> {
    type Error = <StorageVisitor<C> as ValidatedVisitor<HttpSource>>::Error;
    type Context = <StorageVisitor<C> as ValidatedVisitor<HttpSource>>::Context;

    async fn visit_context(
        &self,
        context: &ValidationContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.next.next.visit_context(context).await
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<HttpSource>>,
    ) -> Result<(), Self::Error> {
        let file = result.url().to_string();

        self.next.report.lock().tick();

        let result = self.next.next.visit_sbom(context, result).await;

        if let Err(err) = &result {
            match err {
                StorageError::Validation(ValidationError::Retrieval(err)) => {
                    self.next.report.lock().add_error(
                        Phase::Retrieval,
                        file,
                        format!("retrieval of document failed: {err}"),
                    );

                    // handle client error as non-retry error

                    if let RetrievalError::Source {
                        err: HttpSourceError::Fetcher(fetcher::Error::Request(err)),
                        discovered: _,
                    } = err
                        && let Some(status) = err.status()
                        && self.ignore_errors.contains(&status)
                    {
                        return Ok(());
                    }
                }
                StorageError::Validation(ValidationError::DigestMismatch {
                    expected,
                    actual,
                    ..
                }) => {
                    self.next.report.lock().add_error(
                        Phase::Validation,
                        file,
                        format!("digest mismatch - expected: {expected}, actual: {actual}"),
                    );

                    // If there's a digest error, we can't do much other than ignoring the
                    // current file. Once it gets updated, we can reprocess it.
                    return Ok(());
                }
                StorageError::Validation(ValidationError::Signature { error, .. }) => {
                    self.next.report.lock().add_error(
                        Phase::Validation,
                        file,
                        format!("unable to verify signature: {error}"),
                    );

                    // If there's a signature error, we can't do much other than ignoring the
                    // current file. Once it gets updated, we can reprocess it.
                    return Ok(());
                }
                StorageError::Processing(err) => {
                    self.next.report.lock().add_error(
                        Phase::Upload,
                        file,
                        format!("processing failed: {err}"),
                    );

                    // The file seems corrupt in some way, we can't deal with it until it got
                    // updated.
                    return Ok(());
                }
                StorageError::Storage(err) => {
                    self.next.report.lock().add_error(
                        Phase::Upload,
                        file,
                        format!("upload failed: {err}"),
                    );

                    match &err {
                        // db errors fail and bubble up
                        service::Error::Db(_) => {}
                        _ => {
                            // all others just get logged
                            return Ok(());
                        }
                    }
                }
                StorageError::Canceled => {
                    // propagate up
                    return Err(StorageError::Canceled);
                }
            }
        }

        result
    }
}
