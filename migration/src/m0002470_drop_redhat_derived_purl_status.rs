//! Backfill `advisory.publisher_namespace` of CSAF advisories, and remove the `affected` ranges
//! which ingestion used to derive from the `fixed` versions of Red Hat advisories.
//!
//! The derived ranges (`< fixed`) are now inferred by the correlation engine instead. Red Hat
//! CSAF documents never state such ranges themselves, so they can be identified by their shape:
//! no lower bound, and an exclusive upper bound equal to a `fixed` version of the same advisory,
//! vulnerability and package.

use crate::data::{
    MigrationTraitWithData, SchemaDataManager,
    advisory::{Advisory, Id},
};
use sea_orm::{ConnectionTrait, DatabaseTransaction, DbBackend, Statement};
use sea_orm_migration::prelude::*;
use url::Url;

#[derive(DeriveMigrationName)]
pub struct Migration;

const REDHAT_HOST: &str = "www.redhat.com";

const DELETE_DERIVED: &str = r#"
DELETE FROM purl_status ps
USING version_range vr, status s
WHERE ps.advisory_id = $1
    AND vr.id = ps.version_range_id
    AND s.id = ps.status_id
    AND s.slug = 'affected'
    AND vr.low_version IS NULL
    AND vr.high_version IS NOT NULL
    AND vr.high_inclusive = false
    AND EXISTS (
        SELECT 1
        FROM purl_status f
        JOIN version_range fr ON fr.id = f.version_range_id
        JOIN status fs ON fs.id = f.status_id
        WHERE f.advisory_id = ps.advisory_id
            AND f.vulnerability_id = ps.vulnerability_id
            AND f.base_purl_id = ps.base_purl_id
            AND fs.slug = 'fixed'
            AND fr.low_version = vr.high_version
            AND fr.high_version = vr.high_version
    )
"#;

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        manager
            .process(self, async |advisory, id: Id, tx: &DatabaseTransaction| {
                let Advisory::Csaf(csaf) = advisory else {
                    return Ok(());
                };

                let namespace = csaf.document.publisher.namespace.to_string();

                tx.execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "UPDATE advisory SET publisher_namespace = $1 WHERE id = $2",
                    [namespace.clone().into(), id.advisory.into()],
                ))
                .await?;

                let is_redhat = Url::parse(&namespace)
                    .ok()
                    .is_some_and(|url| url.host_str() == Some(REDHAT_HOST));
                if is_redhat {
                    tx.execute(Statement::from_sql_and_values(
                        DbBackend::Postgres,
                        DELETE_DERIVED,
                        [id.advisory.into()],
                    ))
                    .await?;
                }

                Ok(())
            })
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaDataManager) -> Result<(), DbErr> {
        // the derived ranges can only be restored by re-ingesting with an older version
        Ok(())
    }
}
