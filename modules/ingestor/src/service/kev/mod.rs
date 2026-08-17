pub mod schema;

use crate::{
    graph::{
        error::Error as GraphError,
        exploit::{ExploitCreator, ExploitEntry},
    },
    model::IngestResult,
    service::Error,
};
use hex::ToHex;
use schema::{KevCatalog, KevEntry};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::Serialize;
use time::{Date, macros::format_description};
use tracing::instrument;
use trustify_common::hashing::Digests;
use trustify_entity::labels::Labels;

/// Source identifier for entries originating from the CISA KEV catalog.
pub const SOURCE_CISA_KEV: &str = "cisa-kev";

/// Label key selecting the source identifier under which the entries of the
/// ingested document are stored. Defaults to [`SOURCE_CISA_KEV`] when absent.
pub const LABEL_CATALOG: &str = "catalog";

/// Loads CISA KEV catalog documents into the `exploit` table.
#[derive(Default)]
pub struct KevLoader {}

impl KevLoader {
    /// Create a new loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a catalog document, replacing all entries of its source.
    ///
    /// The source defaults to [`SOURCE_CISA_KEV`] and can be overridden via the
    /// [`LABEL_CATALOG`] label.
    #[instrument(skip(self, catalog, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        labels: Labels,
        catalog: KevCatalog,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let source = labels
            .get(LABEL_CATALOG)
            .map(String::as_str)
            .unwrap_or(SOURCE_CISA_KEV);

        let mut dropped = DroppedDates::default();
        let mut creator = ExploitCreator::new(source);

        for entry in catalog.vulnerabilities {
            let date_reported = parse_date(
                &entry.cve_id,
                "dateAdded",
                entry.date_added.as_deref(),
                &mut dropped,
            );
            let remediation_due_date = parse_date(
                &entry.cve_id,
                "dueDate",
                entry.due_date.as_deref(),
                &mut dropped,
            );

            creator.add(ExploitEntry {
                metadata: serde_json::to_value(KevMetadata::from(&entry))?,
                cve_id: entry.cve_id,
                date_reported,
                remediation_due_date,
            });
        }

        // The creator refuses to replace a source with an empty set. That is a
        // property of the document we were handed, so report it as invalid
        // content (400) rather than as an internal graph failure (500).
        creator.create(tx).await.map_err(|err| match err {
            err @ GraphError::EmptyExploitSet(_) => Error::InvalidContent(err.into()),
            err => err.into(),
        })?;

        Ok(IngestResult {
            // Returning the digest as "id", as no source_document is created
            // for catalog documents. Same approach as the CWE catalog loader.
            id: digests.sha512.encode_hex(),
            document_id: Some(format!("{source}/{}", catalog.catalog_version)),
            warnings: dropped.into_warnings(),
        })
    }
}

/// The CISA-specific payload of a KEV entry, stored as `exploit.metadata`.
///
/// Absent fields are omitted rather than stored as JSON `null`, so that a
/// containment query on the column does not have to distinguish the two.
#[derive(Debug, Serialize)]
struct KevMetadata<'e> {
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_project: Option<&'e str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<&'e str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vulnerability_name: Option<&'e str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_description: Option<&'e str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_action: Option<&'e str>,
    /// Deliberately a free-form string, not an enum: the set of values
    /// ("Known" / "Unknown" today) is owned by the upstream catalog, and new
    /// values must not break ingestion.
    #[serde(skip_serializing_if = "Option::is_none")]
    known_ransomware_campaign_use: Option<&'e str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'e str>,
    /// Kept as the catalog's plain identifiers rather than linked to the
    /// `weakness` entity: the CWE catalog may not be ingested at all.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    cwes: &'e [String],
}

impl<'e> From<&'e KevEntry> for KevMetadata<'e> {
    fn from(entry: &'e KevEntry) -> Self {
        Self {
            vendor_project: entry.vendor_project.as_deref(),
            product: entry.product.as_deref(),
            vulnerability_name: entry.vulnerability_name.as_deref(),
            short_description: entry.short_description.as_deref(),
            required_action: entry.required_action.as_deref(),
            known_ransomware_campaign_use: entry.known_ransomware_campaign_use.as_deref(),
            notes: entry.notes.as_deref(),
            cwes: &entry.cwes,
        }
    }
}

/// How many individual dropped dates to name in the ingest result.
const MAX_DROPPED_DATE_EXAMPLES: usize = 5;

/// Dropped dates, kept as a few examples plus a count. A catalog whose date
/// format we do not understand at all would otherwise return one warning per
/// entry — thousands of near-identical strings for a single underlying fault.
#[derive(Default)]
struct DroppedDates {
    examples: Vec<String>,
    total: usize,
}

impl DroppedDates {
    fn add(&mut self, message: String) {
        self.total += 1;
        if self.examples.len() < MAX_DROPPED_DATE_EXAMPLES {
            self.examples.push(message);
        }
    }

    fn into_warnings(self) -> Vec<String> {
        if self.total == 0 {
            return vec![];
        }

        tracing::warn!(total = self.total, "dropped unparsable catalog dates");

        let mut warnings = self.examples;
        if self.total > warnings.len() {
            warnings.push(format!(
                "dropped {} unparsable dates in total, {} shown",
                self.total,
                warnings.len()
            ));
        }
        warnings
    }
}

/// Parse a catalog date (e.g. "2021-12-10"). Unparsable dates are dropped rather
/// than failing the whole catalog, and collected into `dropped`.
fn parse_date(
    cve_id: &str,
    field: &str,
    value: Option<&str>,
    dropped: &mut DroppedDates,
) -> Option<Date> {
    let value = value?;

    match Date::parse(value, format_description!("[year]-[month]-[day]")) {
        Ok(date) => Some(date),
        Err(err) => {
            // per-occurrence detail at debug; the total is warned once
            tracing::debug!(cve_id, field, value, %err, "dropping unparsable catalog date");
            dropped.add(format!(
                "{cve_id}: dropping unparsable {field} {value:?}: {err}"
            ));
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::EntityTrait;
    use test_context::test_context;
    use test_log::test;
    use time::macros::date;
    use trustify_entity::exploit;
    use trustify_test_context::{TrustifyContext, document_bytes};

    /// Load a document, surfacing the loader's own error type so that tests can
    /// assert on how a failure is classified.
    async fn load_with_labels(
        ctx: &TrustifyContext,
        path: &str,
        labels: Labels,
    ) -> Result<IngestResult, Error> {
        let bytes = document_bytes(path).await.map_err(Error::Generic)?;
        let catalog = serde_json::from_slice(&bytes)?;
        let digests = trustify_common::hashing::Digests::digest(&bytes);
        let loader = KevLoader::new();

        ctx.db
            .transaction(async |tx| loader.load(labels, catalog, &digests, tx).await)
            .await
    }

    async fn load(ctx: &TrustifyContext, path: &str) -> Result<IngestResult, Error> {
        load_with_labels(ctx, path, Labels::default()).await
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let result = load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        assert_eq!(result.document_id.as_deref(), Some("cisa-kev/2025.07.28"));
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);

        let entries = exploit::Entity::find().all(&ctx.db).await?;
        assert_eq!(entries.len(), 3);

        let log4shell = entries
            .iter()
            .find(|e| e.cve_id == "CVE-2021-44228")
            .expect("log4shell entry must exist");
        assert_eq!(log4shell.source, SOURCE_CISA_KEV);
        assert_eq!(log4shell.date_reported, Some(date!(2021 - 12 - 10)));
        assert_eq!(log4shell.remediation_due_date, Some(date!(2021 - 12 - 24)));
        assert_eq!(
            log4shell.id,
            crate::graph::exploit::entry_id(SOURCE_CISA_KEV, "CVE-2021-44228"),
            "the id must be derived from source and CVE id"
        );

        // the CISA-specific payload lands in the metadata
        assert_eq!(
            log4shell.metadata,
            serde_json::json!({
                "vendor_project": "Apache",
                "product": "Log4j2",
                "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
                "short_description": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.",
                "required_action": "For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks.",
                "known_ransomware_campaign_use": "Known",
                "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "cwes": ["CWE-917", "CWE-20"],
            })
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_twice_is_idempotent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        let before = exploit::Entity::find().all(&ctx.db).await?;

        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        let after = exploit::Entity::find().all(&ctx.db).await?;

        assert_eq!(after.len(), 3);
        // content-derived ids keep row identity stable across a full resync
        assert_eq!(
            before.iter().map(|e| e.id).collect::<Vec<_>>(),
            after.iter().map(|e| e.id).collect::<Vec<_>>()
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn minimal_entry_with_unparsable_date(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        let result = load(ctx, "kev/known_exploited_vulnerabilities-minimal.json").await?;

        let entries = exploit::Entity::find().all(&ctx.db).await?;
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.cve_id, "CVE-2099-0001");
        // the unparsable date is dropped, not the entry, and it is reported
        assert_eq!(entry.date_reported, None);
        assert_eq!(entry.remediation_due_date, None);
        assert_eq!(entry.metadata, serde_json::json!({}));
        assert_eq!(
            result.warnings,
            vec![
                r#"CVE-2099-0001: dropping unparsable dateAdded "not-a-date": the 'year' component could not be parsed"#
            ]
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn removed_entries_are_dropped(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        load(
            ctx,
            "kev/known_exploited_vulnerabilities-entry-removed.json",
        )
        .await?;

        let entries = exploit::Entity::find().all(&ctx.db).await?;
        assert_eq!(entries.len(), 2);
        assert!(
            !entries.iter().any(|e| e.cve_id == "CVE-2023-35078"),
            "entry removed from the catalog must be removed from the database"
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn revised_entries_are_updated(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        load(
            ctx,
            "kev/known_exploited_vulnerabilities-entry-revised.json",
        )
        .await?;

        let revised = exploit::Entity::find_by_id(crate::graph::exploit::entry_id(
            SOURCE_CISA_KEV,
            "CVE-2023-35078",
        ))
        .one(&ctx.db)
        .await?
        .expect("revised entry must exist");

        // an ON CONFLICT DO NOTHING insert would have kept the old values here
        assert_eq!(revised.remediation_due_date, Some(date!(2026 - 01 - 31)));
        assert_eq!(
            revised.metadata["required_action"],
            "Apply mitigations per vendor instructions or discontinue use of the product."
        );
        assert_eq!(revised.metadata["known_ransomware_campaign_use"], "Known");

        Ok(())
    }

    /// The creator owns the refusal; this covers how the loader classifies it.
    /// An empty document is bad input, so it must surface as invalid content
    /// (400), not as an internal graph failure (500).
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn empty_catalog_is_rejected_as_invalid_content(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;

        let err = load(ctx, "kev/known_exploited_vulnerabilities-empty.json")
            .await
            .expect_err("an empty catalog must be rejected");
        assert!(
            matches!(err, Error::InvalidContent(_)),
            "must be classified as invalid content, got: {err:?}"
        );

        // the existing entries survive the rejected load
        assert_eq!(exploit::Entity::find().all(&ctx.db).await?.len(), 3);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn catalog_label_overrides_source(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        load_with_labels(
            ctx,
            "kev/known_exploited_vulnerabilities.json",
            Labels::from_one(LABEL_CATALOG, "mirror"),
        )
        .await?;

        // each source keeps its own set of entries
        let entries = exploit::Entity::find().all(&ctx.db).await?;
        assert_eq!(entries.len(), 6);
        assert_eq!(entries.iter().filter(|e| e.source == "mirror").count(), 3);

        // reloading one source replaces only that source's entries
        load_with_labels(
            ctx,
            "kev/known_exploited_vulnerabilities-entry-removed.json",
            Labels::from_one(LABEL_CATALOG, "mirror"),
        )
        .await?;

        let entries = exploit::Entity::find().all(&ctx.db).await?;
        assert_eq!(entries.iter().filter(|e| e.source == "mirror").count(), 2);
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.source == SOURCE_CISA_KEV)
                .count(),
            3
        );

        Ok(())
    }

    /// A catalog whose dates are all malformed must not return one warning per
    /// entry.
    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn dropped_dates_are_capped(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        let entries = (0..50)
            .map(|i| {
                serde_json::json!({
                    "cveID": format!("CVE-2099-{i:04}"),
                    "dateAdded": "17/07/2025",
                    "dueDate": "07/08/2025",
                })
            })
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "catalogVersion": "2025.07.28",
            "vulnerabilities": entries,
        }))?;

        let digests = trustify_common::hashing::Digests::digest(&bytes);
        let result = ctx
            .db
            .transaction(async |tx| {
                KevLoader::new()
                    .load(
                        Labels::default(),
                        serde_json::from_slice(&bytes)?,
                        &digests,
                        tx,
                    )
                    .await
            })
            .await?;

        // every entry is still ingested, dates simply dropped
        assert_eq!(exploit::Entity::find().all(&ctx.db).await?.len(), 50);

        // 100 bad dates collapse to a handful of examples plus a total
        assert_eq!(result.warnings.len(), MAX_DROPPED_DATE_EXAMPLES + 1);
        assert_eq!(
            result.warnings.last().map(String::as_str),
            Some("dropped 100 unparsable dates in total, 5 shown")
        );

        Ok(())
    }
}
