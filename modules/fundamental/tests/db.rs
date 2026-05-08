use sea_orm::{AccessMode, ConnectionTrait, DbBackend, Statement, TransactionTrait};
use test_context::test_context;
use test_log::test;
use trustify_common::db::{DbError, ReadOnly, ReadWrite};
use trustify_test_context::TrustifyContext;

/// ReadOnly::begin() opens a transaction that PostgreSQL enforces as read-only.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn read_only_begin_rejects_writes(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let ro = ReadOnly::new(ctx.db.clone());
    let tx = ro.begin().await?;

    let result = tx
        .execute(Statement::from_string(
            DbBackend::Postgres,
            "CREATE TEMP TABLE _ro_test (id int)".to_string(),
        ))
        .await;

    assert!(
        result.is_err(),
        "write must fail on a read-only transaction"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("read-only"),
        "error should mention read-only, got: {err}"
    );

    Ok(())
}

/// ReadOnly::begin_with_config rejects an explicit ReadWrite access mode
/// before even reaching the database.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn read_only_begin_with_config_rejects_read_write(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    let ro = ReadOnly::new(ctx.db.clone());
    let result = ro
        .begin_with_config(None, Some(AccessMode::ReadWrite))
        .await;

    assert!(
        matches!(result, Err(DbError::ReadOnly)),
        "explicit ReadWrite must be rejected at the Rust level"
    );

    Ok(())
}

/// ReadWrite allows writes through its transaction.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn read_write_allows_writes(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let rw = ReadWrite::new(ctx.db.clone());
    let tx = rw.begin().await?;

    tx.execute(Statement::from_string(
        DbBackend::Postgres,
        "CREATE TEMP TABLE _rw_test (id int)".to_string(),
    ))
    .await?;

    tx.rollback().await?;

    Ok(())
}

/// ReadOnly allows read queries without error.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn read_only_allows_reads(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let ro = ReadOnly::new(ctx.db.clone());
    let tx = ro.begin().await?;

    tx.query_one(Statement::from_string(
        DbBackend::Postgres,
        "SELECT 1 AS n".to_string(),
    ))
    .await?;

    Ok(())
}
