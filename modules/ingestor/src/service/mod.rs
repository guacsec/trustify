pub mod advisory;
pub mod dataset;
mod detect;
pub mod kev;
pub mod sbom;
pub mod validation;
pub mod weakness;

mod format;
mod json;
pub use detect::{DetectedDocument, DocumentDetector, WireFormat};
pub use format::Format;
pub use json::JsonSource;

use crate::graph::Graph;
use crate::graph::error::Error as GraphError;
use crate::{
    model::IngestResult,
    service::{
        dataset::{DatasetIngestResult, DatasetLoader},
        validation::{
            Finding, OnError, Severity, ValidationMode, ValidationOutcome, ValidationReport,
            Validator, ValidatorInput,
        },
    },
};
use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use anyhow::anyhow;
use jsonpath_rust::parser::errors::JsonPathError;
use parking_lot::Mutex;
use sbom_walker::report::ReportSink;
use sea_orm::error::DbErr;
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::{fmt::Debug, sync::Arc, time::Instant};
use tokio::task::JoinError;
use tracing::instrument;
use trustify_common::db::change::{ChangeEntity, ChangeOperation, record_change};
use trustify_common::{db::DatabaseErrors, error::ErrorInformation, id::IdError};
use trustify_entity::labels::Labels;
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::{StorageBackend, dispatch::DispatchBackend};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    HashKey(#[from] IdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    JsonPath(#[from] JsonPathError),
    #[error(transparent)]
    Xml(#[from] roxmltree::Error),
    #[error(transparent)]
    Yaml(#[from] serde_yml::Error),
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Db(DbErr),
    #[error("storage error: {0}")]
    Storage(#[source] anyhow::Error),
    #[error(transparent)]
    Generic(anyhow::Error),
    #[error("invalid content: {0}")]
    InvalidContent(#[source] anyhow::Error),
    #[error("invalid format: {0}")]
    UnsupportedFormat(String),
    #[error("failed to await the task: {0}")]
    Join(#[from] JoinError),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("unavailable")]
    Unavailable,
    #[error("document rejected by validation")]
    ValidationRejected(Vec<ValidationReport>),
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        if value.is_read_only() {
            Error::Unavailable
        } else {
            Error::Db(value)
        }
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::Json(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::JsonPath(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "JsonPath".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Yaml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "YamlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Xml(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "XmlParse".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Io(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "I/O".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Utf8(err) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "UTF-8".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Storage(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Storage".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Join(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Join".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Db(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Database".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Graph(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Graph".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::Generic(err) => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Generic".into(),
                message: err.to_string(),
                details: None,
            }),
            Self::InvalidContent(details) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "InvalidContent".into(),
                message: "Invalid content".to_string(),
                details: Some(details.to_string()),
            }),
            Self::UnsupportedFormat(fmt) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "UnsupportedFormat".into(),
                message: format!("Unsupported document format: {fmt}"),
                details: None,
            }),
            Error::HashKey(inner) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "Digest key error".into(),
                message: inner.to_string(),
                details: None,
            }),
            Self::Zip(inner) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "ZipError".into(),
                message: inner.to_string(),
                details: None,
            }),
            Self::PayloadTooLarge => HttpResponse::PayloadTooLarge().json(ErrorInformation {
                error: "PayloadTooLarge".into(),
                message: self.to_string(),
                details: None,
            }),
            Self::Unavailable => HttpResponse::ServiceUnavailable().json(ErrorInformation {
                error: "Unavailable".into(),
                message: self.to_string(),
                details: None,
            }),
            Self::ValidationRejected(reports) => {
                // Return the reports as a structured array (not an escaped JSON
                // string) so clients can consume findings directly. The
                // `error`/`message` fields mirror `ErrorInformation`.
                HttpResponse::UnprocessableEntity().json(serde_json::json!({
                    "error": "ValidationRejected",
                    "message": self.to_string(),
                    "validation": reports,
                }))
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[schema(rename_all = "camelCase")]
pub enum Cache {
    /// Skip loading into cache
    #[default]
    Skip,
    /// Queue a request to load into cache
    Queue,
    /// Queue and await request to load into cache
    Wait,
}

impl From<Cache> for Option<bool> {
    fn from(value: Cache) -> Self {
        match value {
            Cache::Skip => None,
            Cache::Queue => Some(false),
            Cache::Wait => Some(true),
        }
    }
}

#[derive(Clone)]
pub struct IngestorService {
    graph: Graph,
    storage: DispatchBackend,
    analysis: Option<AnalysisService>,
    validators: Arc<[Arc<dyn Validator>]>,
}

impl IngestorService {
    pub fn new(
        graph: Graph,
        storage: impl Into<DispatchBackend>,
        analysis: Option<AnalysisService>,
    ) -> Self {
        Self {
            graph,
            storage: storage.into(),
            analysis,
            validators: Vec::new().into(),
        }
    }

    /// Attach the set of semantic validators run on every ingest.
    ///
    /// With an empty set (the default), ingestion behaves as if validation did
    /// not exist. See ADR 00020.
    pub fn with_validators(mut self, validators: Vec<Arc<dyn Validator>>) -> Self {
        self.validators = validators.into();
        self
    }

    pub fn storage(&self) -> &DispatchBackend {
        &self.storage
    }

    /// Run all applicable validators against a document.
    ///
    /// Returns the collected reports on success. Returns
    /// [`Error::ValidationRejected`] if any [`ValidationMode::Verify`] validator
    /// blocks the document — either because its outcome is
    /// [`ValidationOutcome::Failed`], or because it errored while configured to
    /// [`OnError::Block`].
    #[instrument(skip(self, bytes), fields(bytes = bytes.len()), err(level = tracing::Level::INFO))]
    async fn run_validators(
        &self,
        bytes: &[u8],
        fmt: Format,
    ) -> Result<Vec<ValidationReport>, Error> {
        run_validators(&self.validators, bytes, fmt).await
    }

    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn ingest(
        &self,
        bytes: &[u8],
        format: Format,
        labels: impl Into<Labels> + Debug,
        issuer: Option<String>,
        cache: Cache,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let start = Instant::now();

        let detector = DocumentDetector::detect_as(bytes, format)?;
        let fmt = detector.format();

        // Run semantic validators before persisting anything. A blocking
        // (verify) failure returns an error here, so no bytes are stored and no
        // graph rows are created. See ADR 00020.
        let reports = self.run_validators(bytes, fmt).await?;

        let result = self
            .storage
            .store(bytes)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;

        let mut result = detector
            .load(&self.graph, labels.into(), issuer, &result.digests, tx)
            .await?;

        attach_validation(&mut result, reports);

        let change_entity = match fmt {
            Format::CSAF | Format::CVE | Format::OSV => Some(ChangeEntity::Advisory),
            Format::SPDX | Format::CycloneDX => Some(ChangeEntity::Sbom),
            _ => None,
        };
        if let Some(entity_type) = change_entity {
            record_change(
                tx,
                entity_type,
                uuid::Uuid::try_parse(&result.id).ok(),
                ChangeOperation::Added,
            )
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;
        }

        if let Some(wait) = cache.into() {
            self.load_graph_cache(fmt, &result, wait).await;
        }

        let duration = start.elapsed();
        tracing::debug!(
            "Ingested: {} ({:?}): took {}",
            result.id,
            result.document_id,
            humantime::Duration::from(duration),
        );

        Ok(result)
    }

    /// Ingest a dataset archive
    #[instrument(skip(self, bytes, tx), err(level=tracing::Level::INFO))]
    pub async fn ingest_dataset(
        &self,
        bytes: &[u8],
        labels: impl Into<Labels> + Debug,
        limit: usize,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<DatasetIngestResult, Error> {
        let loader = DatasetLoader::new(&self.graph, self.storage(), limit);
        loader.load(labels.into(), bytes, tx).await
    }

    /// If appropriate, load result into analysis graph cache
    #[instrument(skip(self))]
    async fn load_graph_cache(&self, fmt: Format, result: &IngestResult, wait: bool) {
        let Some(analysis) = &self.analysis else {
            // if we don't have an instance, we skip
            return;
        };

        let (Format::SPDX | Format::CycloneDX) = fmt else {
            // wrong format, we skip that too
            return;
        };

        match analysis.queue_load(&result.id) {
            Ok(r) if wait => {
                // queued ok, await processing
                if let Err(err) = r.await {
                    tracing::warn!("Failed to await queue load: {err}");
                }
            }
            Ok(_) => {
                // queued ok, don't wait
            }
            Err(e) => {
                // failed to queue
                tracing::warn!("Error queuing graph load for SBOM {}: {e}", result.id);
            }
        }
    }
}

/// Run all applicable validators against a document.
///
/// Returns the collected reports, or [`Error::ValidationRejected`] if a
/// [`ValidationMode::Verify`] validator blocks the document. See ADR 00020.
async fn run_validators(
    validators: &[Arc<dyn Validator>],
    bytes: &[u8],
    fmt: Format,
) -> Result<Vec<ValidationReport>, Error> {
    if validators.is_empty() {
        return Ok(Vec::new());
    }

    let input = ValidatorInput { bytes, format: fmt };
    let mut reports = Vec::new();
    let mut blocked = Vec::new();

    for validator in validators {
        if !validator.applies_to(fmt) {
            continue;
        }

        match validator.validate(&input).await {
            Ok(report) => {
                log_report(fmt, &report);
                if validator.mode() == ValidationMode::Verify
                    && report.outcome == ValidationOutcome::Failed
                {
                    blocked.push(report.clone());
                }
                reports.push(report);
            }
            Err(err) => match (validator.mode(), validator.on_error()) {
                (ValidationMode::Verify, OnError::Block) => {
                    tracing::warn!(
                        validator = validator.name(),
                        "verify validator errored, blocking ingestion: {err}"
                    );
                    blocked.push(errored_report(validator.name(), &err));
                }
                _ => {
                    tracing::warn!(
                        validator = validator.name(),
                        "validator errored, continuing ingestion: {err}"
                    );
                }
            },
        }
    }

    if blocked.is_empty() {
        Ok(reports)
    } else {
        let validators = blocked
            .iter()
            .map(|report| report.validator.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::warn!(
            format = %fmt,
            validators = %validators,
            "document rejected by validation ({} report(s))",
            blocked.len(),
        );
        Err(Error::ValidationRejected(blocked))
    }
}

/// Log a validation report and its findings.
///
/// The report summary logs at `info`; individual findings log at a level that
/// reflects their severity, so operators can see validation outcomes in the
/// server log without needing the ingest API response.
fn log_report(fmt: Format, report: &ValidationReport) {
    tracing::info!(
        validator = %report.validator,
        format = %fmt,
        outcome = ?report.outcome,
        findings = report.findings.len(),
        "semantic validation report"
    );
    for finding in &report.findings {
        let path = finding.path.as_deref().unwrap_or("-");
        match finding.severity {
            Severity::Fatal | Severity::Error => tracing::warn!(
                validator = %report.validator,
                severity = ?finding.severity,
                path,
                "{}",
                finding.message,
            ),
            Severity::Warning => tracing::info!(
                validator = %report.validator,
                severity = ?finding.severity,
                path,
                "{}",
                finding.message,
            ),
            Severity::Info => tracing::debug!(
                validator = %report.validator,
                severity = ?finding.severity,
                path,
                "{}",
                finding.message,
            ),
        }
    }
}

/// Build a report representing a validator that failed to run.
fn errored_report(name: &str, err: &validation::ValidatorError) -> ValidationReport {
    ValidationReport {
        validator: name.to_string(),
        findings: vec![Finding {
            severity: Severity::Fatal,
            message: format!("validator failed to run: {err}"),
            path: None,
            rule: None,
        }],
        outcome: ValidationOutcome::Failed,
    }
}

/// Attach validation reports to an ingest result, folding notable findings into
/// the human-readable `warnings` list for backward compatibility.
fn attach_validation(result: &mut IngestResult, reports: Vec<ValidationReport>) {
    for report in &reports {
        for finding in &report.findings {
            if finding.severity >= Severity::Warning {
                result
                    .warnings
                    .push(format!("[{}] {}", report.validator, finding.message));
            }
        }
    }
    result.validation = reports;
}

/// Capture warnings from the import process
#[derive(Default)]
pub(crate) struct Warnings(Arc<Mutex<Vec<String>>>);

impl Warnings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, msg: String) {
        self.0.lock().push(msg);
    }
}

impl ReportSink for Warnings {
    fn error(&self, msg: String) {
        self.add(msg)
    }
}

impl From<Warnings> for Vec<String> {
    fn from(value: Warnings) -> Self {
        match Arc::try_unwrap(value.0) {
            Ok(warnings) => warnings.into_inner(),
            Err(warnings) => warnings.lock().clone(),
        }
    }
}

pub struct Discard;

impl ReportSink for Discard {
    fn error(&self, _msg: String) {}
}

#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::service::validation::{
        Finding, OnError, Severity, ValidationMode, ValidationOutcome, ValidationReport, Validator,
        ValidatorError, ValidatorInput,
    };
    use sea_orm::prelude::async_trait;

    /// A configurable mock validator for exercising the runner.
    #[derive(Debug)]
    struct MockValidator {
        name: &'static str,
        mode: ValidationMode,
        on_error: OnError,
        applies: bool,
        result: MockResult,
    }

    #[derive(Debug, Clone, Copy)]
    enum MockResult {
        Passed,
        Failed,
        Errored,
    }

    impl MockValidator {
        fn new(name: &'static str, mode: ValidationMode, result: MockResult) -> Self {
            Self {
                name,
                mode,
                on_error: OnError::Block,
                applies: true,
                result,
            }
        }

        fn on_error(mut self, on_error: OnError) -> Self {
            self.on_error = on_error;
            self
        }

        fn applies(mut self, applies: bool) -> Self {
            self.applies = applies;
            self
        }
    }

    #[async_trait::async_trait]
    impl Validator for MockValidator {
        fn name(&self) -> &str {
            self.name
        }
        fn mode(&self) -> ValidationMode {
            self.mode
        }
        fn threshold(&self) -> Severity {
            Severity::Error
        }
        fn on_error(&self) -> OnError {
            self.on_error
        }
        fn applies_to(&self, _format: Format) -> bool {
            self.applies
        }
        async fn validate(
            &self,
            _input: &ValidatorInput<'_>,
        ) -> Result<ValidationReport, ValidatorError> {
            match self.result {
                MockResult::Errored => Err(ValidatorError::Timeout),
                outcome => Ok(ValidationReport {
                    validator: self.name.to_string(),
                    findings: vec![Finding {
                        severity: Severity::Error,
                        message: "finding".into(),
                        path: None,
                        rule: None,
                    }],
                    outcome: match outcome {
                        MockResult::Passed => ValidationOutcome::Passed,
                        _ => ValidationOutcome::Failed,
                    },
                }),
            }
        }
    }

    fn run(validators: Vec<Arc<dyn Validator>>) -> Result<Vec<ValidationReport>, Error> {
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(run_validators(&validators, b"{}", Format::CSAF))
    }

    #[test]
    fn empty_set_is_noop() {
        let reports = run(vec![]).expect("ok");
        assert!(reports.is_empty());
    }

    #[test]
    fn report_mode_never_blocks_even_when_failed() {
        let reports = run(vec![Arc::new(MockValidator::new(
            "r",
            ValidationMode::Report,
            MockResult::Failed,
        ))])
        .expect("report mode must not block");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].outcome, ValidationOutcome::Failed);
    }

    #[test]
    fn verify_mode_blocks_on_failed() {
        let err = run(vec![Arc::new(MockValidator::new(
            "v",
            ValidationMode::Verify,
            MockResult::Failed,
        ))])
        .expect_err("verify + failed must block");
        match err {
            Error::ValidationRejected(reports) => assert_eq!(reports.len(), 1),
            other => panic!("expected ValidationRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_mode_passes_when_ok() {
        let reports = run(vec![Arc::new(MockValidator::new(
            "v",
            ValidationMode::Verify,
            MockResult::Passed,
        ))])
        .expect("verify + passed must not block");
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn verify_error_is_fail_closed_by_default() {
        let err = run(vec![Arc::new(MockValidator::new(
            "v",
            ValidationMode::Verify,
            MockResult::Errored,
        ))])
        .expect_err("verify validator error must block (fail-closed)");
        match err {
            Error::ValidationRejected(reports) => {
                assert_eq!(reports[0].outcome, ValidationOutcome::Failed);
                assert_eq!(reports[0].findings[0].severity, Severity::Fatal);
            }
            other => panic!("expected ValidationRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_error_can_be_fail_open() {
        let reports = run(vec![Arc::new(
            MockValidator::new("v", ValidationMode::Verify, MockResult::Errored)
                .on_error(OnError::Continue),
        )])
        .expect("on_error=continue must not block");
        assert!(reports.is_empty());
    }

    #[test]
    fn non_applicable_validator_is_skipped() {
        let reports = run(vec![Arc::new(
            MockValidator::new("v", ValidationMode::Verify, MockResult::Failed).applies(false),
        )])
        .expect("non-applicable validator must be skipped");
        assert!(reports.is_empty());
    }
}
