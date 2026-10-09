//! Persistence and retrieval of [`ValidationReport`]s.
//!
//! The store is **append-only**. A validator run inserts a row only when its
//! result differs from the latest stored result for the same document and
//! validator; an unchanged re-run writes nothing at all. That keeps the
//! repeated-ingest path — the dominant importer case — free of row updates,
//! and preserves the history of how a verdict changed when a ruleset changes.
//!
//! Rows are keyed by the document's SHA-256 rather than by a `source_document`
//! foreign key, because documents rejected by a `verify` validator are recorded
//! too, and those never reach storage.

use crate::service::validation::{
    Finding, Severity, ValidationMode, ValidationOutcome, ValidationReport,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, JoinType, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Select,
};
use sea_query::Condition;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::id::{Id, IdError};
use trustify_entity::{advisory, sbom, sbom_node, source_document, validation_report};
use uuid::Uuid;

pub use trustify_entity::validation_report::{IngestSource, Model as StoredReport};

/// An error raised while reading or writing validation reports.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The database rejected the query.
    #[error(transparent)]
    Database(#[from] DbErr),
    /// The document identifier could not be turned into a filter.
    #[error(transparent)]
    Id(#[from] IdError),
    /// The findings could not be serialized for storage.
    #[error("failed to serialize findings: {0}")]
    Serialize(#[source] serde_json::Error),
}

/// Bounds on how much of a report is written.
///
/// Validator output is untrusted and unbounded: a loose ruleset against a large
/// document can produce megabytes of findings. Capping them bounds both the
/// serialization work on the ingest path and the row size.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
pub struct Caps {
    #[serde(default = "default_max_findings")]
    /// Maximum number of findings stored per report.
    pub max_findings: usize,
    /// Maximum serialized size of the stored findings, in bytes.
    #[serde(default = "default_max_findings_bytes")]
    pub max_findings_bytes: usize,
}

fn default_max_findings() -> usize {
    200
}

fn default_max_findings_bytes() -> usize {
    64 * 1024
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_findings: default_max_findings(),
            max_findings_bytes: default_max_findings_bytes(),
        }
    }
}

/// How a document reached the ingestor.
///
/// Set on the service rather than passed per call: every construction site
/// already knows what it is, and the importers build their own instance per
/// run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Provenance {
    /// Uploaded through the API.
    Api,
    /// Fetched by the named importer.
    Importer(String),
    /// Loaded as part of a dataset archive.
    Dataset,
    /// Ingested by internal code, including tests.
    #[default]
    Internal,
}

impl Provenance {
    fn source(&self) -> IngestSource {
        match self {
            Self::Api => IngestSource::Api,
            Self::Importer(_) => IngestSource::Importer,
            Self::Dataset => IngestSource::Dataset,
            Self::Internal => IngestSource::Internal,
        }
    }

    fn importer(&self) -> Option<&str> {
        match self {
            Self::Importer(name) => Some(name),
            _ => None,
        }
    }
}

/// Where a document came from, and under which configuration it was validated.
#[derive(Clone, Copy, Debug)]
pub struct PersistContext<'a> {
    /// SHA-256 of the raw document, as lowercase hex.
    pub document_sha256: &'a str,
    /// How the document entered the system.
    pub ingest_source: IngestSource,
    /// Name of the importer, when `ingest_source` is [`IngestSource::Importer`].
    pub importer_name: Option<&'a str>,
    /// Bounds on how much of each report is stored.
    pub caps: Caps,
}

impl<'a> PersistContext<'a> {
    /// Build the context for a document, taking provenance from the service.
    pub fn new(document_sha256: &'a str, provenance: &'a Provenance, caps: Caps) -> Self {
        Self {
            document_sha256,
            ingest_source: provenance.source(),
            importer_name: provenance.importer(),
            caps,
        }
    }
}

/// One validator result awaiting persistence.
#[derive(Clone, Copy, Debug)]
pub struct PendingReport<'a> {
    /// The report produced by the validator.
    pub report: &'a ValidationReport,
    /// The mode the validator ran in.
    pub mode: ValidationMode,
    /// True when this result rejected the document.
    pub blocked: bool,
    /// Digest of the configuration that produced the result.
    pub config_fingerprint: &'a str,
}

/// Store the reports whose result differs from the latest stored one.
///
/// Returns the number of rows inserted; zero means every result was already
/// recorded. Reads the latest content hashes in one query and writes the new
/// rows in one statement, so the cost is at most two round trips per document
/// regardless of how many validators ran.
#[instrument(skip_all, fields(document = ctx.document_sha256), err(level = tracing::Level::INFO))]
pub async fn persist_if_changed<'a, C: ConnectionTrait>(
    conn: &C,
    ctx: &PersistContext<'_>,
    pending: impl IntoIterator<Item = PendingReport<'a>>,
) -> Result<usize, Error> {
    let pending = pending.into_iter().collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(0);
    }

    let names = pending
        .iter()
        .map(|entry| entry.report.validator.as_str())
        .collect::<Vec<_>>();
    let known = latest_content_hashes(conn, ctx.document_sha256, names).await?;

    let mut models = Vec::with_capacity(pending.len());
    for entry in pending {
        let (model, content_hash) = to_model(ctx, &entry)?;
        if known.get(&entry.report.validator) == Some(&content_hash) {
            continue;
        }
        models.push(model);
    }

    let inserted = models.len();
    if inserted > 0 {
        validation_report::Entity::insert_many(models)
            .exec(conn)
            .await?;
    }

    Ok(inserted)
}

/// The latest content hash per validator for one document.
async fn latest_content_hashes<'a, C: ConnectionTrait>(
    conn: &C,
    document_sha256: &str,
    validators: impl IntoIterator<Item = &'a str>,
) -> Result<HashMap<String, String>, Error> {
    /// Only the columns needed to decide whether a result changed — notably
    /// not `findings`, which can be tens of kilobytes per row.
    #[derive(Debug, sea_orm::FromQueryResult)]
    struct Row {
        validator: String,
        content_hash: String,
    }

    let rows = validation_report::Entity::find()
        .select_only()
        .column(validation_report::Column::Validator)
        .column(validation_report::Column::ContentHash)
        .filter(validation_report::Column::DocumentSha256.eq(document_sha256))
        .filter(validation_report::Column::Validator.is_in(validators))
        // Newest last, so later rows overwrite earlier ones in the map below.
        .order_by_asc(validation_report::Column::CreatedAt)
        .into_model::<Row>()
        .all(conn)
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| (row.validator, row.content_hash))
        .collect())
}

/// The current result of every validator that has run against one document.
///
/// Bounded by the number of validators, not by history: older rows for the same
/// validator are discarded.
#[instrument(skip(conn), err(level = tracing::Level::INFO))]
pub async fn latest_for_digest<C: ConnectionTrait>(
    conn: &C,
    document_sha256: &str,
) -> Result<Vec<StoredReport>, Error> {
    let mut latest = HashMap::new();
    for report in by_digest(document_sha256)
        .order_by_asc(validation_report::Column::CreatedAt)
        .all(conn)
        .await?
    {
        latest.insert(report.validator.clone(), report);
    }

    let mut reports = latest.into_values().collect::<Vec<_>>();
    reports.sort_by(|left, right| left.validator.cmp(&right.validator));
    Ok(reports)
}

/// Every report recorded for a document digest, newest first.
///
/// Composable: callers add their own ordering, pagination or filters.
pub fn by_digest(document_sha256: &str) -> Select<validation_report::Entity> {
    validation_report::Entity::find()
        .filter(validation_report::Column::DocumentSha256.eq(document_sha256))
}

/// Every report recorded for the document identified by `id`.
///
/// Accepts an internal UUID (of an SBOM or an advisory) or any supported
/// digest. A UUID or a non-SHA-256 digest resolves through `source_document`,
/// so it only matches documents that were actually ingested — a rejected
/// document can only be found by its SHA-256.
pub fn by_document_id(id: Id) -> Result<Select<validation_report::Entity>, Error> {
    // The common case needs no join: the digest is the stored key.
    if let Id::Sha256(sha256) = &id {
        return Ok(by_digest(sha256));
    }

    let query = validation_report::Entity::find().join(
        JoinType::InnerJoin,
        validation_report::Relation::SourceDocument.def(),
    );

    Ok(match id {
        Id::Uuid(uuid) => query
            .join_rev(JoinType::LeftJoin, sbom::Relation::SourceDocument.def())
            .join_rev(JoinType::LeftJoin, advisory::Relation::SourceDocument.def())
            .filter(
                Condition::any()
                    .add(sbom::Column::SbomId.eq(uuid))
                    .add(advisory::Column::Id.eq(uuid)),
            ),
        Id::Sha384(digest) => query.filter(source_document::Column::Sha384.eq(digest)),
        Id::Sha512(digest) => query.filter(source_document::Column::Sha512.eq(digest)),
        id => return Err(Error::Id(IdError::UnsupportedAlgorithm(id.to_string()))),
    })
}

/// Every report recorded for documents with the given name.
///
/// Matches the name of the SBOM's describing node and the advisory identifier.
/// Neither is unique, so this can span several documents; callers are expected
/// to paginate.
pub fn by_document_name(name: &str) -> Select<validation_report::Entity> {
    validation_report::Entity::find()
        .join(
            JoinType::InnerJoin,
            validation_report::Relation::SourceDocument.def(),
        )
        .join_rev(JoinType::LeftJoin, sbom::Relation::SourceDocument.def())
        .join(JoinType::LeftJoin, sbom::Relation::SbomNode.def())
        .join_rev(JoinType::LeftJoin, advisory::Relation::SourceDocument.def())
        .filter(
            Condition::any()
                .add(sbom_node::Column::Name.eq(name))
                .add(advisory::Column::Identifier.eq(name)),
        )
}

/// Build the row for one pending report, returning it with its content hash.
fn to_model(
    ctx: &PersistContext<'_>,
    entry: &PendingReport<'_>,
) -> Result<(validation_report::ActiveModel, String), Error> {
    let finding_count = entry.report.findings.len();
    let max_severity = entry
        .report
        .findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .map(map_severity);

    let (findings, truncated) = truncate(&entry.report.findings, ctx.caps)?;
    let mode = map_mode(entry.mode);
    let outcome = map_outcome(entry.report.outcome);

    // Everything that distinguishes one result from another, including the
    // configuration that produced it, so that a ruleset change records a new
    // row even when the findings are identical.
    let mut hasher = Sha256::new();
    for part in [
        entry.report.validator.as_str(),
        &mode.to_string(),
        &outcome.to_string(),
        &entry.blocked.to_string(),
        &max_severity.map(|s| s.to_string()).unwrap_or_default(),
        &finding_count.to_string(),
        &truncated.to_string(),
        entry.config_fingerprint,
        &findings.to_string(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    let content_hash = hex::encode(hasher.finalize());

    let model = validation_report::ActiveModel {
        id: Set(Uuid::now_v7()),
        document_sha256: Set(ctx.document_sha256.to_owned()),
        validator: Set(entry.report.validator.clone()),
        mode: Set(mode),
        outcome: Set(outcome),
        blocked: Set(entry.blocked),
        max_severity: Set(max_severity),
        // Saturates rather than wrapping; a report with more than 2^31 findings
        // is not a number anyone needs to be exact about.
        finding_count: Set(i32::try_from(finding_count).unwrap_or(i32::MAX)),
        findings: Set(findings),
        truncated: Set(truncated),
        content_hash: Set(content_hash.clone()),
        config_fingerprint: Set(entry.config_fingerprint.to_owned()),
        ingest_source: Set(ctx.ingest_source),
        importer_name: Set(ctx.importer_name.map(str::to_owned)),
        created_at: Set(OffsetDateTime::now_utc()),
    };

    Ok((model, content_hash))
}

/// Serialize findings, dropping entries until they fit within `caps`.
///
/// Bounds both the work done on the ingest path and the row size: validator
/// output is untrusted, and a loose ruleset against a large document can
/// otherwise produce megabytes of JSON per report.
fn truncate(findings: &[Finding], caps: Caps) -> Result<(serde_json::Value, bool), Error> {
    let mut kept = findings.len().min(caps.max_findings);
    loop {
        let value = serde_json::to_value(&findings[..kept]).map_err(Error::Serialize)?;
        if kept == 0 || value.to_string().len() <= caps.max_findings_bytes {
            return Ok((value, kept < findings.len()));
        }
        kept /= 2;
    }
}

fn map_mode(mode: ValidationMode) -> validation_report::Mode {
    match mode {
        ValidationMode::Report => validation_report::Mode::Report,
        ValidationMode::Verify => validation_report::Mode::Verify,
    }
}

fn map_outcome(outcome: ValidationOutcome) -> validation_report::Outcome {
    match outcome {
        ValidationOutcome::Passed => validation_report::Outcome::Passed,
        ValidationOutcome::Failed => validation_report::Outcome::Failed,
    }
}

fn map_severity(severity: Severity) -> validation_report::Severity {
    match severity {
        Severity::Info => validation_report::Severity::Info,
        Severity::Warning => validation_report::Severity::Warning,
        Severity::Error => validation_report::Severity::Error,
        Severity::Fatal => validation_report::Severity::Fatal,
    }
}

/// Resolve the `source_document` digest for an ingested document, if it exists.
///
/// Used by callers that hold a document's internal ID and need the key this
/// store is organised by.
#[instrument(skip(conn), err(level = tracing::Level::INFO))]
pub async fn digest_for_document<C: ConnectionTrait>(
    conn: &C,
    id: Id,
) -> Result<Option<String>, Error> {
    if let Id::Sha256(sha256) = id {
        return Ok(Some(sha256));
    }

    let digest = source_document::Entity::find()
        .join_rev(JoinType::LeftJoin, sbom::Relation::SourceDocument.def())
        .join_rev(JoinType::LeftJoin, advisory::Relation::SourceDocument.def())
        .filter(match id {
            Id::Uuid(uuid) => Condition::any()
                .add(sbom::Column::SbomId.eq(uuid))
                .add(advisory::Column::Id.eq(uuid)),
            Id::Sha384(digest) => Condition::all().add(source_document::Column::Sha384.eq(digest)),
            Id::Sha512(digest) => Condition::all().add(source_document::Column::Sha512.eq(digest)),
            Id::Sha256(digest) => Condition::all().add(source_document::Column::Sha256.eq(digest)),
            id => return Err(Error::Id(IdError::UnsupportedAlgorithm(id.to_string()))),
        })
        .one(conn)
        .await?;

    Ok(digest.map(|document| document.sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::validation::Finding;
    use test_context::test_context;
    use test_log::test;
    use trustify_test_context::TrustifyContext;

    const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn report(findings: Vec<Finding>, outcome: ValidationOutcome) -> ValidationReport {
        ValidationReport {
            validator: "test-validator".to_string(),
            findings,
            outcome,
        }
    }

    fn finding(severity: Severity, message: &str) -> Finding {
        Finding {
            severity,
            message: message.to_string(),
            path: None,
            rule: None,
        }
    }

    fn context(document_sha256: &str) -> PersistContext<'_> {
        PersistContext {
            document_sha256,
            ingest_source: IngestSource::Internal,
            importer_name: None,
            caps: Caps::default(),
        }
    }

    fn pending<'a>(report: &'a ValidationReport, fingerprint: &'a str) -> PendingReport<'a> {
        PendingReport {
            report,
            mode: ValidationMode::Report,
            blocked: false,
            config_fingerprint: fingerprint,
        }
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn unchanged_result_writes_nothing(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let report = report(vec![], ValidationOutcome::Passed);

        let inserted =
            persist_if_changed(&ctx.db, &context(DIGEST), [pending(&report, "fp-1")]).await?;
        assert_eq!(inserted, 1);

        // The same result from a later run must not produce a second row: this
        // is what keeps repeated importer ingests off the write path.
        let inserted =
            persist_if_changed(&ctx.db, &context(DIGEST), [pending(&report, "fp-1")]).await?;
        assert_eq!(inserted, 0);

        assert_eq!(by_digest(DIGEST).all(&ctx.db).await?.len(), 1);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn changed_result_appends(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let digest = &DIGEST.replace("1", "2");

        let passed = report(vec![], ValidationOutcome::Passed);
        persist_if_changed(&ctx.db, &context(digest), [pending(&passed, "fp-1")]).await?;

        let failed = report(
            vec![finding(Severity::Error, "missing field")],
            ValidationOutcome::Failed,
        );
        let inserted =
            persist_if_changed(&ctx.db, &context(digest), [pending(&failed, "fp-1")]).await?;
        assert_eq!(inserted, 1);

        // History is kept, and the newer verdict is the current one.
        assert_eq!(by_digest(digest).all(&ctx.db).await?.len(), 2);

        let latest = latest_for_digest(&ctx.db, digest).await?;
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].outcome, validation_report::Outcome::Failed);
        assert_eq!(latest[0].finding_count, 1);
        assert_eq!(
            latest[0].max_severity,
            Some(validation_report::Severity::Error)
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn changed_configuration_appends(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let digest = &DIGEST.replace("1", "3");
        let report = report(vec![], ValidationOutcome::Passed);

        persist_if_changed(&ctx.db, &context(digest), [pending(&report, "fp-1")]).await?;

        // Same verdict, different ruleset: the row records which configuration
        // produced it, so a new row is required to stay accurate.
        let inserted =
            persist_if_changed(&ctx.db, &context(digest), [pending(&report, "fp-2")]).await?;
        assert_eq!(inserted, 1);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn findings_are_capped(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let digest = &DIGEST.replace("1", "4");
        let findings = (0..10)
            .map(|i| finding(Severity::Warning, &format!("finding {i}")))
            .collect();
        let report = report(findings, ValidationOutcome::Passed);

        let mut ctx_with_caps = context(digest);
        ctx_with_caps.caps = Caps {
            max_findings: 3,
            max_findings_bytes: 64 * 1024,
        };
        persist_if_changed(&ctx.db, &ctx_with_caps, [pending(&report, "fp-1")]).await?;

        let stored = latest_for_digest(&ctx.db, digest).await?;
        assert!(stored[0].truncated);
        // The count reports everything the validator found, even though only
        // the capped subset is stored.
        assert_eq!(stored[0].finding_count, 10);
        assert_eq!(stored[0].findings.as_array().map(Vec::len), Some(3));

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn resolves_by_document_id_and_name(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = ctx
            .ingest_document("zookeeper-3.9.2-cyclonedx.json")
            .await?;
        let digest = digest_for_document(&ctx.db, Id::Uuid(Uuid::parse_str(&result.id)?))
            .await?
            .expect("ingested document has a source document");

        let report = report(vec![], ValidationOutcome::Passed);
        persist_if_changed(&ctx.db, &context(&digest), [pending(&report, "fp-1")]).await?;

        let by_id = by_document_id(Id::Uuid(Uuid::parse_str(&result.id)?))?
            .all(&ctx.db)
            .await?;
        assert_eq!(by_id.len(), 1);

        let by_name = by_document_name("zookeeper").all(&ctx.db).await?;
        assert_eq!(by_name.len(), 1);

        Ok(())
    }
}
