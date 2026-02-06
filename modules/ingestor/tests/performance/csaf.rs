use std::time::Instant;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest_medium_1(ctx: TrustifyContext) -> anyhow::Result<()> {
    let start = Instant::now();

    let _result = ctx.ingest_document("csaf/rhsa-2024-2705.json").await?;

    let ingest_time = start.elapsed();
    log::info!("ingest: {}", humantime::Duration::from(ingest_time));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest_medium_2(ctx: TrustifyContext) -> anyhow::Result<()> {
    let start = Instant::now();

    let _result = ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let ingest_time = start.elapsed();
    log::info!("ingest: {}", humantime::Duration::from(ingest_time));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest_large_1(ctx: TrustifyContext) -> anyhow::Result<()> {
    let start = Instant::now();

    let _result = ctx.ingest_document("csaf/cve-2024-2961.json.xz").await?;

    let ingest_time = start.elapsed();
    log::info!("ingest: {}", humantime::Duration::from(ingest_time));

    Ok(())
}
