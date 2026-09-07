// Make a fully-unbounded version range (both bounds NULL) match any version, so
// a bare CSAF `known_affected` (version-less) becomes matchable instead of being
// silently dropped by the per-scheme comparators. See TC-5732.
//
// Implemented as a CREATE OR REPLACE of the `version_matches` dispatcher, so it
// is idempotent and safe to re-run (which also keeps any future 0.4.z -> 0.6.z
// upgrade path clean regardless of the migration name recorded upstream).
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0002260_version_matches_unbounded/version_matches_up.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0002260_version_matches_unbounded/version_matches_down.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }
}
