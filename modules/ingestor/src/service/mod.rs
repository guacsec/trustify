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
            Finding, InvocationError, OnError, Severity, ValidationMode, ValidationOutcome,
            ValidationReport, Validator, ValidatorInput, store, store::Provenance,
        },
    },
};
use actix_web::{HttpResponse, ResponseError, body::BoxBody};
use anyhow::anyhow;
use hex::ToHex;
use jsonpath_rust::parser::errors::JsonPathError;
use parking_lot::Mutex;
use sbom_walker::report::ReportSink;
use sea_orm::error::DbErr;
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::{fmt::Debug, sync::Arc, time::Instant};
use tokio::task::JoinError;
use tracing::instrument;
use trustify_common::{
    db::{
        DatabaseErrors, ReadWrite,
        change::{ChangeEntity, ChangeOperation, record_change},
    },
    error::ErrorInformation,
    hashing::Contexts,
    id::IdError,
};
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
    provenance: Arc<Provenance>,
    /// Connection used to record rejections, which must outlive the caller's
    /// rolled-back transaction.
    reports: Option<ReadWrite>,
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
            provenance: Arc::new(Provenance::default()),
            reports: None,
        }
    }

    /// Attach the registered validators available to ingestion and internal callers.
    ///
    /// With an empty set (the default), ingestion behaves as if validation did
    /// not exist. See ADR 00021.
    pub fn with_validators(mut self, validators: Vec<Arc<dyn Validator>>) -> Self {
        self.validators = validators.into();
        self
    }

    /// Declare how documents reach this instance, recorded with every report.
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Arc::new(provenance);
        self
    }

    /// Attach the connection used to record documents rejected by validation.
    ///
    /// A rejection is refused ingestion, so the caller's transaction is rolled
    /// back and anything written on it is lost. Without this connection, a
    /// rejection is only logged.
    pub fn with_report_store(mut self, db: ReadWrite) -> Self {
        self.reports = Some(db);
        self
    }

    pub fn storage(&self) -> &DispatchBackend {
        &self.storage
    }

    /// Invoke one named validator directly, without ingestion gating or storage.
    pub async fn validate_named(
        &self,
        name: &str,
        bytes: &[u8],
        format: Format,
    ) -> Result<ValidationReport, InvocationError> {
        let input = ValidatorInput { bytes, format };
        validation::validate_named(&self.validators, name, &input).await
    }

    /// Run all applicable validators against a document.
    #[instrument(skip(self, bytes), fields(bytes = bytes.len()))]
    async fn run_validators(&self, bytes: &[u8], fmt: Format) -> Vec<Validated> {
        run_validators(&self.validators, bytes, fmt).await
    }

    /// Record the results that asked to be stored.
    ///
    /// Never fails the caller: the document is already ingested, so losing the
    /// audit trail is worth a warning, not a rolled-back ingest.
    async fn store_reports<C: ConnectionTrait>(
        &self,
        conn: &C,
        document_sha256: &str,
        validated: &[Validated],
    ) {
        let pending = validated
            .iter()
            .filter(|entry| entry.persist)
            .map(|entry| store::PendingReport {
                report: &entry.report,
                mode: entry.mode,
                blocked: entry.blocked,
                config_fingerprint: &entry.fingerprint,
            })
            .collect::<Vec<_>>();

        for entry in validated.iter().filter(|entry| !entry.persist) {
            tracing::debug!(
                validator = %entry.report.validator,
                outcome = ?entry.report.outcome,
                "validation report not persisted"
            );
        }

        if pending.is_empty() {
            return;
        }

        let context = store::PersistContext::new(
            document_sha256,
            &self.provenance,
            self.caps().unwrap_or_default(),
        );
        match store::persist_if_changed(conn, &context, pending).await {
            Ok(0) => tracing::debug!("validation reports unchanged"),
            Ok(count) => tracing::debug!("recorded {count} validation report(s)"),
            Err(err) => tracing::warn!("failed to record validation reports: {err}"),
        }
    }

    /// Record a document that validation refused.
    ///
    /// Runs on its own connection: the caller rolls back on the error returned
    /// here, which would take the record with it. Failing to record a rejection
    /// must not change the rejection itself, so errors are logged only.
    async fn record_rejection(&self, bytes: &[u8], fmt: Format, validated: &[Validated]) {
        let Some(db) = &self.reports else {
            tracing::debug!(
                format = %fmt,
                "document rejected by validation; not recorded (no report store configured)"
            );
            return;
        };

        // The document never reaches storage, so nothing has hashed it yet.
        let mut contexts = Contexts::new();
        contexts.update(bytes);
        let document_sha256 = contexts.finish().sha256.encode_hex::<String>();

        let result = db
            .transaction(async |tx| {
                self.store_reports(tx, &document_sha256, validated).await;
                Ok::<_, DbErr>(())
            })
            .await;
        if let Err(err) = result {
            tracing::warn!("failed to record rejected document: {err}");
        }
    }

    /// The caps configured for the validators, which are global.
    fn caps(&self) -> Option<store::Caps> {
        self.validators
            .first()
            .map(|validator| validator.persistence().caps)
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
        // graph rows are created. See ADR 00021.
        let validated = self.run_validators(bytes, fmt).await;

        let blocked = blocking_reports(&validated);
        if !blocked.is_empty() {
            self.record_rejection(bytes, fmt, &validated).await;
            return Err(Error::ValidationRejected(blocked));
        }

        let stored = self
            .storage
            .store(bytes)
            .await
            .map_err(|err| Error::Storage(anyhow!("{err}")))?;
        let document_sha256 = stored.digests.sha256.encode_hex::<String>();

        let mut result = detector
            .load(&self.graph, labels.into(), issuer, &stored.digests, tx)
            .await?;

        // On the caller's transaction: the reports describe a document that is
        // only ingested if that transaction commits.
        self.store_reports(tx, &document_sha256, &validated).await;

        attach_validation(
            &mut result,
            validated.into_iter().map(|entry| entry.report).collect(),
        );

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

/// The outcome of one validator, with what the store needs to record it.
#[derive(Debug)]
struct Validated {
    report: ValidationReport,
    mode: ValidationMode,
    /// True when this result rejects the document.
    blocked: bool,
    /// Digest of the configuration that produced the result.
    fingerprint: String,
    /// Whether the result is stored at all.
    persist: bool,
}

/// Run all applicable validators against a document.
///
/// Returns one entry per validator that ran. Blocking is reported per entry
/// rather than as an error, because a rejected document still has to be
/// recorded before ingestion is refused. See ADR 00021.
async fn run_validators(
    validators: &[Arc<dyn Validator>],
    bytes: &[u8],
    fmt: Format,
) -> Vec<Validated> {
    if validators.is_empty() {
        return Vec::new();
    }

    let input = ValidatorInput { bytes, format: fmt };
    let mut results = Vec::new();

    for validator in validators {
        if !validator.run_on_ingest() || !validator.applies_to(fmt) {
            continue;
        }

        let persistence = validator.persistence();
        match validator.validate(&input).await {
            Ok(report) => {
                log_report(fmt, &report);
                let blocked = validator.mode() == ValidationMode::Verify
                    && report.outcome == ValidationOutcome::Failed;
                results.push(Validated {
                    report,
                    mode: validator.mode(),
                    blocked,
                    fingerprint: persistence.fingerprint.clone(),
                    persist: persistence.persist,
                });
            }
            Err(err) => match (validator.mode(), validator.on_error()) {
                (ValidationMode::Verify, OnError::Block) => {
                    tracing::warn!(
                        validator = validator.name(),
                        "verify validator errored, blocking ingestion: {err}"
                    );
                    results.push(Validated {
                        report: errored_report(validator.name(), &err),
                        mode: ValidationMode::Verify,
                        blocked: true,
                        fingerprint: persistence.fingerprint.clone(),
                        persist: persistence.persist,
                    });
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

    results
}

/// The reports that rejected the document, if any.
fn blocking_reports(validated: &[Validated]) -> Vec<ValidationReport> {
    validated
        .iter()
        .filter(|entry| entry.blocked)
        .map(|entry| entry.report.clone())
        .collect()
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
        Finding, OnError, Persistence, Severity, ValidationMode, ValidationOutcome,
        ValidationReport, Validator, ValidatorError, ValidatorInput,
    };
    use sea_orm::prelude::async_trait;

    /// A configurable mock validator for exercising the runner.
    #[derive(Debug)]
    struct MockValidator {
        name: &'static str,
        mode: ValidationMode,
        on_error: OnError,
        applies: bool,
        run_on_ingest: bool,
        result: MockResult,
        persistence: Persistence,
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
                run_on_ingest: true,
                result,
                persistence: Persistence::default(),
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

        fn run_on_ingest(mut self, run_on_ingest: bool) -> Self {
            self.run_on_ingest = run_on_ingest;
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
        fn run_on_ingest(&self) -> bool {
            self.run_on_ingest
        }
        fn applies_to(&self, _format: Format) -> bool {
            self.applies
        }
        fn persistence(&self) -> &Persistence {
            &self.persistence
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

    /// Mirror how `ingest` turns validator results into an ingest outcome.
    fn run(validators: Vec<Arc<dyn Validator>>) -> Result<Vec<ValidationReport>, Error> {
        let validated = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(run_validators(&validators, b"{}", Format::CSAF));

        let blocked = blocking_reports(&validated);
        match blocked.is_empty() {
            true => Ok(validated.into_iter().map(|entry| entry.report).collect()),
            false => Err(Error::ValidationRejected(blocked)),
        }
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

    #[tokio::test]
    async fn disabled_ingest_validator_remains_invocable_by_name() {
        let validators: Vec<Arc<dyn Validator>> = vec![Arc::new(
            MockValidator::new("internal-only", ValidationMode::Report, MockResult::Failed)
                .run_on_ingest(false),
        )];
        assert!(
            run_validators(&validators, b"{}", Format::CSAF)
                .await
                .is_empty(),
            "validator must be skipped during ingestion"
        );

        let input = ValidatorInput {
            bytes: b"{}",
            format: Format::CSAF,
        };
        let report = validation::validate_named(&validators, "internal-only", &input)
            .await
            .expect("explicit call runs validator");
        assert_eq!(report.outcome, ValidationOutcome::Failed);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use crate::service::validation::{
        Persistence, Severity, ValidationMode, ValidationOutcome, ValidationReport, Validator,
        ValidatorError, ValidatorInput,
        store::{Provenance, StoredReport},
    };
    use sea_orm::{EntityTrait, prelude::async_trait};
    use test_context::test_context;
    use test_log::test;
    use trustify_entity::validation_report;
    use trustify_test_context::{TrustifyContext, document_bytes};

    /// A validator with a fixed verdict, used to exercise the ingest paths.
    #[derive(Debug)]
    struct FixedValidator {
        mode: ValidationMode,
        outcome: ValidationOutcome,
        persistence: Persistence,
    }

    impl FixedValidator {
        fn new(mode: ValidationMode, outcome: ValidationOutcome) -> Self {
            Self {
                mode,
                outcome,
                persistence: Persistence::default(),
            }
        }

        fn persist(mut self, persist: bool) -> Self {
            self.persistence.persist = persist;
            self
        }
    }

    #[async_trait::async_trait]
    impl Validator for FixedValidator {
        fn name(&self) -> &str {
            "fixed"
        }
        fn mode(&self) -> ValidationMode {
            self.mode
        }
        fn threshold(&self) -> Severity {
            Severity::Error
        }
        fn on_error(&self) -> OnError {
            OnError::Block
        }
        fn applies_to(&self, _format: Format) -> bool {
            true
        }
        fn persistence(&self) -> &Persistence {
            &self.persistence
        }
        async fn validate(
            &self,
            _input: &ValidatorInput<'_>,
        ) -> Result<ValidationReport, ValidatorError> {
            Ok(ValidationReport {
                validator: self.name().to_string(),
                findings: vec![],
                outcome: self.outcome,
            })
        }
    }

    async fn ingest(
        ctx: &TrustifyContext,
        validator: FixedValidator,
    ) -> Result<Result<IngestResult, Error>, anyhow::Error> {
        let ingestor = IngestorService::new(Graph::new(), ctx.storage.clone(), None)
            .with_validators(vec![Arc::new(validator)])
            .with_provenance(Provenance::Api)
            .with_report_store(trustify_common::db::ReadWrite::new(ctx.db.clone()));

        let bytes = document_bytes("zookeeper-3.9.2-cyclonedx.json").await?;
        Ok(ctx
            .db
            .transaction(async |tx| {
                ingestor
                    .ingest(
                        &bytes,
                        Format::Unknown,
                        ("source", "test"),
                        None,
                        Cache::Skip,
                        tx,
                    )
                    .await
            })
            .await)
    }

    async fn stored(ctx: &TrustifyContext) -> Result<Vec<StoredReport>, anyhow::Error> {
        Ok(validation_report::Entity::find().all(&ctx.db).await?)
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn report_mode_is_recorded(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ingest(
            ctx,
            FixedValidator::new(ValidationMode::Report, ValidationOutcome::Failed),
        )
        .await?
        .expect("report mode must not block");

        let reports = stored(ctx).await?;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].mode, validation_report::Mode::Report);
        assert!(!reports[0].blocked);
        assert_eq!(
            reports[0].ingest_source,
            validation_report::IngestSource::Api
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn verify_pass_is_recorded(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ingest(
            ctx,
            FixedValidator::new(ValidationMode::Verify, ValidationOutcome::Passed),
        )
        .await?
        .expect("verify + passed must not block");

        let reports = stored(ctx).await?;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].mode, validation_report::Mode::Verify);
        assert!(!reports[0].blocked);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn rejection_survives_rollback(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = ingest(
            ctx,
            FixedValidator::new(ValidationMode::Verify, ValidationOutcome::Failed),
        )
        .await?;
        assert!(matches!(result, Err(Error::ValidationRejected(_))));

        // The ingest transaction rolled back with the rejection, so the record
        // can only be here if it was written on its own connection.
        let reports = stored(ctx).await?;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].blocked);
        assert_eq!(reports[0].outcome, validation_report::Outcome::Failed);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn persist_disabled_writes_nothing(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        ingest(
            ctx,
            FixedValidator::new(ValidationMode::Report, ValidationOutcome::Passed).persist(false),
        )
        .await?
        .expect("ingest");

        assert!(stored(ctx).await?.is_empty());

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn repeated_ingest_does_not_append(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        for _ in 0..3 {
            ingest(
                ctx,
                FixedValidator::new(ValidationMode::Report, ValidationOutcome::Passed),
            )
            .await?
            .expect("ingest");
        }

        // Re-ingesting an unchanged document is the dominant importer case: it
        // must not grow the table.
        assert_eq!(stored(ctx).await?.len(), 1);

        Ok(())
    }
}
