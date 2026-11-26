//! Removing the details of evidence (matched values, confidence factors) no evidence references
//! anymore.
//!
//! Details are stored once per distinct value, outside the transaction of the extraction writing
//! the evidence referencing them (see [`crate::extractor::writer::Target::details`]). Deleted or
//! replaced evidence, as well as failed extractions, leave unreferenced details behind.

use crate::error::Error;
use sea_orm::{ConnectionTrait, TransactionTrait};
use tracing::instrument;
use trustify_common::db::{self, sql};

// Shared by every extraction for its entire transaction (see `freshness::lock_revision`). Taken
// here, no extraction runs: none has written evidence referencing a detail which isn't
// committed yet, and none starts writing before the cleanup ends.
const LOCK_EXTRACTIONS: &str =
    "SELECT revision FROM correlation_extraction_revision FOR NO KEY UPDATE SKIP LOCKED";

const DELETE_MATCHED_VALUES: &str = "DELETE FROM correlation_matched_value m WHERE NOT EXISTS (SELECT 1 FROM correlation_evidence e WHERE e.matched_value_id = m.id)";

const DELETE_CONFIDENCE_FACTORS: &str = "DELETE FROM correlation_confidence_factors f WHERE NOT EXISTS (SELECT 1 FROM correlation_evidence e WHERE e.confidence_factors_id = f.id)";

/// Remove unreferenced details, if no extraction is running. Skipped otherwise.
///
/// Returns the number of details removed, `None` if skipped.
#[instrument(skip_all, err(level = tracing::Level::INFO))]
pub async fn run_step(db: &db::ReadWrite) -> Result<Option<u64>, Error> {
    let tx = db.begin().await?;
    if tx.query_one_raw(sql(LOCK_EXTRACTIONS, [])).await?.is_none() {
        return Ok(None);
    }
    let matched_values = tx
        .execute_raw(sql(DELETE_MATCHED_VALUES, []))
        .await?
        .rows_affected();
    let factors = tx
        .execute_raw(sql(DELETE_CONFIDENCE_FACTORS, []))
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(Some(matched_values + factors))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::freshness::lock_revision;
    use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set};
    use serde_json::json;
    use test_context::test_context;
    use trustify_entity::{
        correlation_confidence_factors, correlation_evidence, correlation_matched_value,
    };
    use trustify_test_context::TrustifyContext;
    use uuid::Uuid;

    /// Only unreferenced details are removed, and only while no extraction runs.
    #[test_context(TrustifyContext)]
    #[test_log::test(tokio::test)]
    async fn removes_unreferenced_details(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let sbom_id = Uuid::parse_str(&ctx.ingest_document("spdx/simple.json").await?.id)?;
        let advisory_id =
            Uuid::parse_str(&ctx.ingest_document("csaf/cve-2023-33201.json").await?.id)?;
        let referenced =
            correlation_matched_value::store(&*ctx.db, json!({"identifier": "referenced"})).await?;
        correlation_matched_value::store(&*ctx.db, json!({"identifier": "unreferenced"})).await?;
        let factors = correlation_confidence_factors::store(&*ctx.db, json!([])).await?;
        correlation_confidence_factors::store(
            &*ctx.db,
            json!([{"factor": 1.0, "reason": {"kind": "purl"}}]),
        )
        .await?;
        correlation_evidence::ActiveModel {
            id: Set(Uuid::new_v4()),
            sbom_id: Set(sbom_id),
            node_id: Set("SPDXRef-Package".into()),
            advisory_id: Set(advisory_id),
            vulnerability_id: Set("CVE-2023-33201".into()),
            status: Set(correlation_evidence::AssertionStatus::Affected),
            confidence: Set(1.0),
            extractor: Set("purl".into()),
            matched_value_id: Set(Some(referenced)),
            confidence_factors_id: Set(factors),
            source_assertions: Set(json!([{"kind": "purl", "id": Uuid::new_v4()}])),
            created_at: Set(time::OffsetDateTime::now_utc()),
        }
        .insert(&*ctx.db)
        .await?;
        let db = db::ReadWrite::new(ctx.db.clone());

        // skipped while an extraction runs
        let extraction = ctx.db.begin().await?;
        lock_revision(&extraction).await?;
        assert_eq!(run_step(&db).await?, None);
        extraction.rollback().await?;

        assert_eq!(run_step(&db).await?, Some(2));
        let matched_values = correlation_matched_value::Entity::find()
            .order_by_asc(correlation_matched_value::Column::Id)
            .all(&*ctx.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>();
        assert_eq!(matched_values, vec![referenced]);
        let factor_sets = correlation_confidence_factors::Entity::find()
            .all(&*ctx.db)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect::<Vec<_>>();
        assert_eq!(factor_sets, vec![factors]);
        Ok(())
    }
}
