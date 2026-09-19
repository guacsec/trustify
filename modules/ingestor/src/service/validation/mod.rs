//! Third-party semantic validators run during ingestion.
//!
//! A [`Validator`] inspects a raw document (before it is parsed into the graph)
//! and returns a structured [`ValidationReport`]. Validators run in one of two
//! modes: [`ValidationMode::Report`] (findings are recorded but never block) or
//! [`ValidationMode::Verify`] (a failing outcome blocks ingestion).
//!
//! See ADR 00020 for the design and rationale.

pub mod config;
pub mod scheck;

pub use config::{Backend, ValidatorConfig, ValidatorsConfig, build};
pub use scheck::ScheckValidator;

use crate::service::Format;
use sea_orm::prelude::async_trait;
use std::fmt::Debug;

/// Severity of a single validation finding.
///
/// Ordered from least to most severe, so `>=` comparisons express a threshold.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Fatal,
}

/// A single validation finding produced by a validator.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct Finding {
    /// The severity of this finding.
    pub severity: Severity,
    /// Human-readable description of the finding.
    pub message: String,
    /// Location within the document (e.g. a JSONPath), when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Identifier of the rule that produced the finding, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

/// Whether a validator considered the document acceptable.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ValidationOutcome {
    /// No finding met the validator's blocking threshold.
    Passed,
    /// At least one finding met the validator's blocking threshold.
    Failed,
}

/// A structured report produced by a single validator run.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ValidationReport {
    /// The [`Validator::name`] that produced this report.
    pub validator: String,
    /// Findings produced by the validator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    /// The overall outcome, derived from the findings and the validator's threshold.
    pub outcome: ValidationOutcome,
}

/// How a validator's findings affect ingestion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    /// Record findings only; never block ingestion.
    #[default]
    Report,
    /// Block ingestion when the outcome is [`ValidationOutcome::Failed`].
    Verify,
}

/// What to do when a [`ValidationMode::Verify`] validator cannot produce a verdict.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    /// Treat an errored validator as a failed gate and block ingestion.
    #[default]
    Block,
    /// Log the error and let ingestion continue.
    Continue,
}

/// Input handed to a validator.
///
/// Borrows the raw bytes; validators must not assume they can outlive the call.
#[derive(Debug)]
pub struct ValidatorInput<'a> {
    /// Raw document bytes, before parsing.
    pub bytes: &'a [u8],
    /// The concrete format resolved by detection.
    pub format: Format,
}

/// An error that prevented a validator from producing a verdict.
///
/// Distinct from a [`ValidationReport`] whose outcome is
/// [`ValidationOutcome::Failed`]: this means the validator itself could not run.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorError {
    /// The validator backend failed to execute.
    #[error("validator backend failed: {0}")]
    Backend(#[source] anyhow::Error),
    /// The validator did not complete within its time budget.
    #[error("validator timed out")]
    Timeout,
}

/// A third-party semantic validator run during ingestion.
///
/// Implementations are shared behind an `Arc` and may run concurrently, so they
/// must be `Send + Sync`.
#[async_trait::async_trait]
pub trait Validator: Send + Sync + Debug {
    /// Stable identifier, used in configuration, reports, and logs.
    fn name(&self) -> &str;

    /// The mode this validator runs in.
    fn mode(&self) -> ValidationMode;

    /// For [`ValidationMode::Verify`], the lowest severity that blocks ingestion.
    fn threshold(&self) -> Severity;

    /// For [`ValidationMode::Verify`], the behaviour when the validator errors.
    fn on_error(&self) -> OnError;

    /// Whether this validator applies to the given document format.
    fn applies_to(&self, format: Format) -> bool;

    /// Run the validator against a document.
    ///
    /// Returns a [`ValidationReport`] on success. Returning `Err` means the
    /// validator could not produce a verdict, which is handled according to
    /// [`Validator::on_error`].
    async fn validate(
        &self,
        input: &ValidatorInput<'_>,
    ) -> Result<ValidationReport, ValidatorError>;
}
