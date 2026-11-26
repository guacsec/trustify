use super::insert_purl_statuses;
use sea_orm::{
    ConnectionTrait, DbBackend, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Statement,
    TransactionTrait,
    sea_query::{Expr, ExprTrait, PgFunc},
};
use serde_json::json;
use std::{env, time::Instant};
use test_context::test_context;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::purl_status;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
async fn array_insert_preserves_rows_and_ignores_conflicts(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    insert_purl_statuses(Vec::new(), &ctx.db).await?;
    ctx.ingest_document("csaf/issues/2740/baseline-branches.json")
        .await?;
    let seed = purl_status::Entity::find()
        .one(&ctx.db)
        .await?
        .expect("fixture must contain a PURL status");

    // Exceed the old 11-column VALUES insert's parameter limit.
    let mut expected = Vec::new();
    for index in 0..6_000 {
        let mut row = seed.clone();
        row.id = Uuid::now_v7();
        row.is_default = index % 2 == 0;
        row.source_provider = match index % 3 {
            0 => None,
            1 => Some(json!(null)),
            _ => Some(json!({"provider": "array insert", "index": index})),
        };
        if index % 2 == 0 {
            row.qualified_purl_id = None;
            row.context_cpe_id = None;
            row.assertion_context_id = None;
        }
        expected.push(row);
    }
    expected.sort_by_key(|row| row.id);
    let models: Vec<_> = expected
        .iter()
        .cloned()
        .map(IntoActiveModel::into_active_model)
        .collect();
    insert_purl_statuses(models.clone(), &ctx.db).await?;
    insert_purl_statuses(models, &ctx.db).await?;

    let ids: Vec<_> = expected.iter().map(|row| row.id).collect();
    let actual = purl_status::Entity::find()
        .filter(Expr::col(purl_status::Column::Id).eq(PgFunc::any(ids)))
        .order_by_asc(purl_status::Column::Id)
        .all(&ctx.db)
        .await?;
    assert_eq!(actual, expected);
    Ok(())
}

/// Compare the previous VALUES implementation with the production array insert.
/// Run with `RUST_LOG=off cargo test -p trustify-module-ingestor --release --lib
/// benchmark_purl_status_inserts -- --ignored --nocapture --test-threads=1`.
#[test_context(TrustifyContext)]
#[test_log::test(tokio::test)]
#[ignore = "manual database performance measurement"]
async fn benchmark_purl_status_inserts(ctx: &TrustifyContext) -> anyhow::Result<()> {
    assert!(
        env::var_os("EXTERNAL_TEST_DB").is_none(),
        "benchmark requires an isolated embedded database"
    );
    ctx.ingest_document("csaf/issues/2740/baseline-branches.json")
        .await?;
    let seeds = purl_status::Entity::find().all(&ctx.db).await?;
    assert!(!seeds.is_empty());
    let tx = ctx.db.begin().await?;
    let version = tx
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT version() AS version",
        ))
        .await?
        .expect("PostgreSQL version");
    println!("Database: {}", version.try_get::<String>("", "version")?);
    println!("Optimized Rust build: {}", !cfg!(debug_assertions));
    println!(
        "One transaction, full schema/indexes/FKs; construction and execution timed; no commit."
    );
    println!("Tables reset outside timing; 3 warmups and 11 alternating-order samples per method.");
    println!(
        "rows,existing_percent,values_median_ms,arrays_median_ms,speedup,values_p25_ms,values_p75_ms,arrays_p25_ms,arrays_p75_ms"
    );

    for size in [10, 100, 1_000, 6_000, 20_000] {
        let mut rows = Vec::with_capacity(size);
        for index in 0..size {
            let mut row = seeds[index % seeds.len()].clone();
            // The production path sorts content-derived UUIDs before insertion.
            row.id = Uuid::new_v5(&Uuid::NAMESPACE_OID, &index.to_le_bytes());
            row.source_provider = if index % 3 == 0 {
                Some(json!({"provider": "benchmark", "index": index}))
            } else {
                None
            };
            rows.push(row.into_active_model());
        }
        rows.sort_by_key(|row| *row.id.as_ref());

        for existing_percent in [0, 50, 100] {
            let mut values_times = Vec::new();
            let mut arrays_times = Vec::new();
            for round in 0..14 {
                for method in 0..2 {
                    let arrays = (round + method) % 2 == 0;
                    // Only the embedded benchmark database is touched. Reset the heap and
                    // indexes so neither method inherits bloat from earlier measurements.
                    tx.execute_unprepared("TRUNCATE purl_status CASCADE")
                        .await?;
                    let existing = size * existing_percent / 100;
                    for batch in rows[..existing].iter().cloned().chunked() {
                        purl_status::Entity::insert_many(batch)
                            .on_conflict_do_nothing()
                            .exec(&tx)
                            .await?;
                    }
                    let input = rows.clone();
                    let start = Instant::now();
                    if arrays {
                        insert_purl_statuses(input, &tx).await?;
                    } else {
                        for batch in input.chunked() {
                            purl_status::Entity::insert_many(batch)
                                .on_conflict_do_nothing()
                                .exec(&tx)
                                .await?;
                        }
                    }
                    let elapsed = start.elapsed().as_secs_f64() * 1_000.0;
                    if round >= 3 {
                        if arrays {
                            arrays_times.push(elapsed);
                        } else {
                            values_times.push(elapsed);
                        }
                    }
                }
            }
            values_times.sort_by(f64::total_cmp);
            arrays_times.sort_by(f64::total_cmp);
            println!(
                "{size},{existing_percent},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
                values_times[5],
                arrays_times[5],
                values_times[5] / arrays_times[5],
                values_times[2],
                values_times[8],
                arrays_times[2],
                arrays_times[8],
            );
        }
    }
    tx.rollback().await?;
    Ok(())
}
