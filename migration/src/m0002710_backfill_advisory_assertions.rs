//! Store what older versions didn't store of the statements of an advisory.
//!
//! Advisories ingested before the statement migrations (up to `m0002580`) have no assertion
//! contexts, CPE, hash or product identifier assertions, remediation assertions or upstream
//! vulnerabilities, and their `purl_status` rows have no PURL, context or default flag. They can't
//! be updated, as the ID of such a row is derived from its content. So the rows are replaced, using
//! what ingestion writes, which makes the result the same as ingesting the document now.
//!
//! The `product_status` rows are replaced too, as they lack CSAF product IDs, and so are the
//! `cpe_status` rows, as older versions wrote different ones.
//!
//! This includes what `m0002480` used to do: `advisory.publisher_namespace`, and dropping the
//! `affected` ranges older versions derived from the `fixed` versions of Red Hat advisories.
//!
//! All SBOMs are extracted again afterwards, which sees all advisories, so the queued advisories
//! would only repeat that work.

use crate::data::{
    Document, MigrationTraitWithData, SchemaDataManager,
    advisory::{Advisory, Id},
};
use anyhow::bail;
use futures_util::FutureExt;
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, FromQueryResult, Statement};
use sea_orm_migration::prelude::*;
use trustify_module_ingestor::{
    graph::Graph,
    service::{
        DetectedDocument, Warnings,
        advisory::{csaf::loader::CsafLoader, cve::loader::CveLoader, osv::loader::OsvLoader},
    },
};
use trustify_module_storage::service::StorageBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Advisories ingested before the last migration changing what ingestion stores, and all CSAF
/// advisories, whose `product_status` rows kept the CSAF product IDs of a random product. Later
/// CVE and OSV records have everything already, and a new database has none of these.
const OLDER_ADVISORIES: &str = r#"
SELECT a.id AS advisory, a.source_document_id AS source
FROM advisory a
JOIN source_document d ON d.id = a.source_document_id
JOIN seaql_migrations m ON m.version = 'm0002580_remediation_assertions'
WHERE d.ingested < to_timestamp(m.applied_at) OR a.publisher_namespace IS NOT NULL
"#;

/// A document of an advisory in [`OLDER_ADVISORIES`].
struct OlderAdvisory(Advisory);

impl Document for OlderAdvisory {
    type Id = Id;

    async fn all<C: ConnectionTrait>(tx: &C) -> Result<Vec<Self::Id>, DbErr> {
        Id::find_by_statement(Statement::from_string(
            DbBackend::Postgres,
            OLDER_ADVISORIES,
        ))
        .all(tx)
        .await
    }

    async fn source<S, C>(id: &Self::Id, storage: &S, tx: &C) -> Result<Self, anyhow::Error>
    where
        S: StorageBackend + Send + Sync,
        C: ConnectionTrait,
    {
        Advisory::source(id, storage, tx).await.map(Self)
    }
}

/// Replace the statements of an advisory.
async fn backfill(advisory: Advisory, id: Id, tx: &DatabaseTransaction) -> anyhow::Result<()> {
    let document = advisory.0;
    if !matches!(
        document,
        DetectedDocument::Csaf(_) | DetectedDocument::Cve(_) | DetectedDocument::Osv(_)
    ) {
        bail!(
            "unable to backfill the statements of advisory {}, keeping them would leave them wrong",
            id.advisory
        );
    }

    tx.execute_unprepared("SET LOCAL trustify.correlation_defer_invalidation = 'on'")
        .await?;
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM purl_status WHERE advisory_id = $1",
        [id.advisory.into()],
    ))
    .await?;
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM product_status WHERE advisory_id = $1",
        [id.advisory.into()],
    ))
    .await?;
    tx.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM cpe_status WHERE advisory_id = $1",
        [id.advisory.into()],
    ))
    .await?;

    let warnings = Warnings::new();
    match document {
        DetectedDocument::Csaf(csaf) => {
            tx.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE advisory SET publisher_namespace = $1 WHERE id = $2",
                [
                    csaf.document.publisher.namespace.to_string().into(),
                    id.advisory.into(),
                ],
            ))
            .await?;
            CsafLoader::backfill_statements(&Graph::new(), &csaf, id.advisory, &warnings, tx)
                .await?;
        }
        DetectedDocument::Cve(record) => {
            CveLoader::backfill_statements(&record, id.advisory, &warnings, tx).await?;
        }
        DetectedDocument::Osv(osv) => {
            OsvLoader::backfill_statements(&osv, id.advisory, &warnings, tx).await?;
        }
        _ => {}
    }

    for warning in Vec::<String>::from(warnings) {
        tracing::info!(advisory = %id.advisory, "Skipped while backfilling: {warning}");
    }

    Ok(())
}

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0002710_backfill_advisory_assertions/up.sql"))
            .await?;

        // waiting for a later run processing the documents
        if manager.should_skip(self) {
            return Ok(());
        }

        // without it, no advisory would count as older, and this would succeed without any work
        let cutoff = manager
            .get_connection()
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT 1 FROM seaql_migrations WHERE version = 'm0002580_remediation_assertions'",
            ))
            .await?;
        if cutoff.is_none() {
            return Err(DbErr::Migration(
                "the schema migrations up to m0002580_remediation_assertions must run first".into(),
            ));
        }

        if OlderAdvisory::all(manager.get_connection())
            .await?
            .is_empty()
        {
            return Ok(());
        }

        manager
            .process(self, |advisory: OlderAdvisory, id: Id, tx| {
                backfill(advisory.0, id, tx).boxed()
            })
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
DELETE FROM correlation_extraction_queue WHERE entity_type = 'advisory';
UPDATE correlation_extraction_revision SET revision = revision + 1;
UPDATE correlation_verdict_revision SET revision = revision + 1, changed_at = clock_timestamp();
"#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        // the old rows can only be restored by ingesting with an older version
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0002710_backfill_advisory_assertions/down.sql"
            ))
            .await?;
        Ok(())
    }
}
