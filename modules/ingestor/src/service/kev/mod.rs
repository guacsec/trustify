pub mod schema;

use crate::{model::IngestResult, service::Error};
use hex::ToHex;
use schema::KevCatalog;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use time::{Date, macros::format_description};
use tracing::instrument;
use trustify_common::{db::chunk::EntityChunkedIter, hashing::Digests};
use trustify_entity::{known_exploited_vulnerability, labels::Labels};

/// Source identifier for entries originating from the CISA KEV catalog.
pub const SOURCE_CISA: &str = "cisa";

#[derive(Default)]
pub struct KevLoader {}

impl KevLoader {
    pub fn new() -> Self {
        Self::default()
    }

    #[instrument(skip(self, catalog, tx), err(level=tracing::Level::INFO))]
    pub async fn load(
        &self,
        _labels: Labels,
        catalog: KevCatalog,
        digests: &Digests,
        tx: &(impl ConnectionTrait + TransactionTrait),
    ) -> Result<IngestResult, Error> {
        let batch = catalog
            .vulnerabilities
            .into_iter()
            .map(|entry| known_exploited_vulnerability::ActiveModel {
                source: Set(SOURCE_CISA.to_string()),
                date_added: Set(entry
                    .date_added
                    .as_deref()
                    .and_then(|value| parse_date(&entry.cve_id, "dateAdded", value))),
                due_date: Set(entry
                    .due_date
                    .as_deref()
                    .and_then(|value| parse_date(&entry.cve_id, "dueDate", value))),
                cve_id: Set(entry.cve_id),
                vendor_project: Set(entry.vendor_project),
                product: Set(entry.product),
                vulnerability_name: Set(entry.vulnerability_name),
                short_description: Set(entry.short_description),
                required_action: Set(entry.required_action),
                known_ransomware_campaign_use: Set(entry.known_ransomware_campaign_use),
                notes: Set(entry.notes),
                cwes: Set(normalize(entry.cwes)),
            })
            .collect::<Vec<_>>();

        // The catalog is authoritative for its source: entries can be removed
        // from KEV again, so each load replaces the full set for the source
        // instead of appending. The surrounding transaction keeps this atomic.
        known_exploited_vulnerability::Entity::delete_many()
            .filter(known_exploited_vulnerability::Column::Source.eq(SOURCE_CISA))
            .exec(tx)
            .await?;

        for chunk in &batch.chunked() {
            known_exploited_vulnerability::Entity::insert_many(chunk)
                .exec(tx)
                .await?;
        }

        Ok(IngestResult {
            // Returning the digest as "id", as no source_document is created
            // for catalog documents. Same approach as the CWE catalog loader.
            id: digests.sha512.encode_hex(),
            document_id: Some("CISA-KEV".to_string()),
            warnings: vec![],
        })
    }
}

/// Parse a catalog date (e.g. "2021-12-10"). Unparsable dates are dropped
/// rather than failing the whole catalog.
fn parse_date(cve_id: &str, field: &str, value: &str) -> Option<Date> {
    match Date::parse(value, format_description!("[year]-[month]-[day]")) {
        Ok(date) => Some(date),
        Err(err) => {
            tracing::warn!(cve_id, field, value, %err, "dropping unparsable catalog date");
            None
        }
    }
}

fn normalize(vec: Vec<String>) -> Option<Vec<String>> {
    if vec.is_empty() { None } else { Some(vec) }
}

#[cfg(test)]
mod test {
    use super::*;
    use sea_orm::EntityTrait;
    use test_context::test_context;
    use test_log::test;
    use time::macros::date;
    use trustify_entity::known_exploited_vulnerability;
    use trustify_test_context::{TrustifyContext, document_bytes};

    async fn load(ctx: &TrustifyContext, path: &str) -> Result<(), anyhow::Error> {
        let bytes = document_bytes(path).await?;
        let catalog = serde_json::from_slice(&bytes)?;
        let digests = trustify_common::hashing::Digests::digest(&bytes);
        let loader = KevLoader::new();

        ctx.db
            .transaction(async |tx| loader.load(Labels::default(), catalog, &digests, tx).await)
            .await?;

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;

        let entries = known_exploited_vulnerability::Entity::find()
            .all(&ctx.db)
            .await?;
        assert_eq!(entries.len(), 3);

        let log4shell = entries
            .iter()
            .find(|e| e.cve_id == "CVE-2021-44228")
            .expect("log4shell entry must exist");
        assert_eq!(log4shell.source, SOURCE_CISA);
        assert_eq!(log4shell.vendor_project.as_deref(), Some("Apache"));
        assert_eq!(log4shell.product.as_deref(), Some("Log4j2"));
        assert_eq!(log4shell.date_added, Some(date!(2021 - 12 - 10)));
        assert_eq!(log4shell.due_date, Some(date!(2021 - 12 - 24)));
        assert_eq!(
            log4shell.known_ransomware_campaign_use.as_deref(),
            Some("Known")
        );
        assert_eq!(
            log4shell.cwes,
            Some(vec!["CWE-917".to_string(), "CWE-20".to_string()])
        );

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn ingest_twice_is_idempotent(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;
        load(ctx, "kev/known_exploited_vulnerabilities.json").await?;

        let entries = known_exploited_vulnerability::Entity::find()
            .all(&ctx.db)
            .await?;
        assert_eq!(entries.len(), 3);

        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test(tokio::test)]
    async fn minimal_entry_with_unparsable_date(
        ctx: &TrustifyContext,
    ) -> Result<(), anyhow::Error> {
        load(ctx, "kev/known_exploited_vulnerabilities-minimal.json").await?;

        let entries = known_exploited_vulnerability::Entity::find()
            .all(&ctx.db)
            .await?;
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.cve_id, "CVE-2099-0001");
        // the unparsable date is dropped, not the entry
        assert_eq!(entry.date_added, None);
        assert_eq!(entry.due_date, None);
        assert_eq!(entry.vendor_project, None);
        assert_eq!(entry.cwes, None);

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

        let entries = known_exploited_vulnerability::Entity::find()
            .all(&ctx.db)
            .await?;
        assert_eq!(entries.len(), 2);
        assert!(
            !entries.iter().any(|e| e.cve_id == "CVE-2023-35078"),
            "entry removed from the catalog must be removed from the database"
        );

        Ok(())
    }
}
