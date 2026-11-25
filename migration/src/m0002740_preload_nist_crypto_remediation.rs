//! Seed an empty remediation table with the bundled NIST-only reference dataset.

use crate::data::{MigrationTraitWithData, SchemaDataManager};
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
use sea_orm_migration::prelude::*;
use serde_json::{Map, Value};
use uuid::Uuid;

/// The sole source of initial reference mappings, embedded at build time.
const MAPPINGS: &str = include_str!(
    "m0002740_preload_nist_crypto_remediation/NIST-Only-PQC-Remediation-2026-11.display.json"
);

/// Preload initial reference mappings without replacing existing data.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTraitWithData for Migration {
    async fn up(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        if manager.should_skip(self) {
            return Ok(());
        }

        let mut mappings: Vec<Map<String, Value>> = serde_json::from_str(MAPPINGS)
            .map_err(|err| DbErr::Migration(format!("Invalid bundled remediation data: {err}")))?;
        for mapping in &mut mappings {
            mapping.insert("id".into(), Uuid::now_v7().to_string().into());
        }
        let mappings = serde_json::to_value(mappings)
            .map_err(|err| DbErr::Migration(format!("Invalid bundled remediation data: {err}")))?;

        let tx = manager.get_connection().begin().await?;
        // Serialize the empty-table check and seed; never merge with another dataset.
        tx.execute_unprepared("LOCK TABLE crypto_remediation IN EXCLUSIVE MODE")
            .await?;
        if tx
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT 1 FROM crypto_remediation LIMIT 1",
            ))
            .await?
            .is_some()
        {
            return Err(DbErr::Migration(
                "crypto_remediation must be empty before initial NIST seeding; existing mappings were left unchanged"
                    .into(),
            ));
        }
        tx.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            include_str!("m0002740_preload_nist_crypto_remediation/up.sql"),
            [mappings.into()],
        ))
        .await?;
        tx.commit().await
    }

    async fn down(&self, manager: &SchemaDataManager) -> Result<(), DbErr> {
        let mappings: Value = serde_json::from_str(MAPPINGS)
            .map_err(|err| DbErr::Migration(format!("Invalid bundled remediation data: {err}")))?;
        // Remove unchanged default mappings only, not customized or unrelated rows.
        manager
            .get_connection()
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                include_str!("m0002740_preload_nist_crypto_remediation/down.sql"),
                [mappings.into()],
            ))
            .await?;
        Ok(())
    }
}
