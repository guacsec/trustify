//! Used to backfill `advisory.publisher_namespace` of CSAF advisories, and remove the `affected`
//! ranges which ingestion derived from the `fixed` versions of Red Hat advisories.
//!
//! `m0002710_backfill_advisory_assertions` does both now, while replacing the statements of older
//! advisories, so that a database which didn't run this yet only parses its documents once.

use crate::data::{MigrationTraitWithData, SchemaDataManager};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, _manager: &SchemaDataManager) -> Result<(), DbErr> {
        Ok(())
    }

    async fn down(&self, _manager: &SchemaDataManager) -> Result<(), DbErr> {
        Ok(())
    }
}
