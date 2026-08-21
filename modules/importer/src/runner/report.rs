use crate::server::RunOutput;
use parking_lot::Mutex;
use schemars::JsonSchema;
use std::{collections::BTreeMap, iter, sync::Arc};
use time::OffsetDateTime;

/// The phase of processing
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    utoipa::ToSchema,
    JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    /// Retrieving the document
    Retrieval,
    /// Validating the retrieved document
    Validation,
    /// Upload to storage
    Upload,
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Start of the import run
    #[serde(with = "time::serde::rfc3339")]
    pub start_date: OffsetDateTime,
    /// End of the import run
    #[serde(with = "time::serde::rfc3339")]
    pub end_date: OffsetDateTime,

    /// Number of processes items
    #[serde(default, alias = "number_of_items")]
    pub number_of_items: usize,
    /// Messages emitted during processing
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub messages: BTreeMap<Phase, BTreeMap<String, Vec<Message>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct Message {
    ///  The severity of the message
    pub severity: Severity,
    /// The message
    pub message: String,
}

impl Message {
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReportBuilder {
    report: Report,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            report: Report {
                start_date: OffsetDateTime::now_utc(),
                end_date: OffsetDateTime::now_utc(),
                number_of_items: 0,
                messages: Default::default(),
            },
        }
    }

    pub fn tick(&mut self) {
        self.report.number_of_items += 1;
    }

    /// Add a single message
    pub fn add_message(
        &mut self,
        phase: Phase,
        file: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
    ) {
        self.extend_messages(
            phase,
            file,
            [Message {
                severity,
                message: message.into(),
            }],
        )
    }

    /// Add a single error
    pub fn add_error(&mut self, phase: Phase, file: impl Into<String>, message: impl Into<String>) {
        self.add_message(phase, file, Severity::Error, message)
    }

    pub fn extend_messages(
        &mut self,
        phase: Phase,
        file: impl Into<String>,
        messages: impl IntoIterator<Item = Message>,
    ) {
        let file = file.into();
        let mut messages = messages.into_iter();

        // check if we have at least one item

        let first = messages.next();
        let Some(first) = first else {
            // if not, return without creating any phase or file
            return;
        };

        // now add the first, and all remaining messages

        self.report
            .messages
            .entry(phase)
            .or_default()
            .entry(file)
            .or_default()
            .extend(iter::once(first).chain(messages));
    }

    pub fn build(mut self) -> Report {
        self.report.end_date = OffsetDateTime::now_utc();
        self.report
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReportVisitor<V> {
    pub report: Arc<Mutex<ReportBuilder>>,
    pub next: V,
}

impl<V> ReportVisitor<V> {
    pub fn new(report: Arc<Mutex<ReportBuilder>>, next: V) -> Self {
        Self { report, next }
    }
}

/// Fail a scanner process.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// A critical error occurred, we don't even have a report.
    #[error(transparent)]
    Critical(#[from] anyhow::Error),
    /// A normal error occurred, we did capture some information in the report.
    #[error("{err}")]
    Normal {
        #[source]
        err: anyhow::Error,
        output: Box<RunOutput>,
    },
}

pub trait SplitScannerError {
    /// Split a [`ScannerError`] into a result and an output, unless it was critical.
    fn split(self) -> anyhow::Result<(RunOutput, anyhow::Result<()>)>;
}

impl SplitScannerError for Result<RunOutput, ScannerError> {
    fn split(self) -> anyhow::Result<(RunOutput, anyhow::Result<()>)> {
        match self {
            Ok(output) => Ok((output, Ok(()))),
            Err(ScannerError::Normal { err, output }) => Ok((*output, Err(err))),
            Err(ScannerError::Critical(err)) => Err(err),
        }
    }
}
