#![allow(clippy::expect_used)]

use anyhow::bail;
use std::time::Instant;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn ingest(ctx: TrustifyContext) -> anyhow::Result<()> {
    let start = Instant::now();

    let _result = ctx.ingest_document("csaf/cve-2023-33201.json").await?;

    let ingest_time = start.elapsed();

    log::info!("ingest: {}", humantime::Duration::from(ingest_time));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
async fn reingest(ctx: TrustifyContext) -> anyhow::Result<()> {
    async fn assert(ctx: &TrustifyContext, result: IngestResult) -> anyhow::Result<()> {
        let Ok(id) = Uuid::parse_str(&result.id) else {
            bail!("must be a UUID")
        };
        let adv = ctx
            .graph
            .get_advisory_by_id(id, &ctx.db)
            .await?
            .expect("must be found");

        assert_eq!(adv.vulnerabilities(&ctx.db).await?.len(), 1);

        let all = adv.vulnerabilities(&ctx.db).await?;
        assert_eq!(all.len(), 1);
        assert_eq!(
            all[0].advisory_vulnerability.vulnerability_id,
            "CVE-2023-33201"
        );

        let all = ctx.graph.get_vulnerabilities(&ctx.db).await?;
        assert_eq!(all.len(), 1);

        let vuln = ctx
            .graph
            .get_vulnerability("CVE-2023-33201", &ctx.db)
            .await?
            .expect("Must be found");

        assert_eq!(vuln.vulnerability.id, "CVE-2023-33201");

        let descriptions = vuln.descriptions("en", &ctx.db).await?;
        assert_eq!(descriptions.len(), 0);

        Ok(())
    }

    // ingest the first time

    let result = ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    assert(&ctx, result).await?;

    // ingest a second time

    let result = ctx.ingest_document("csaf/cve-2023-33201.json").await?;
    assert(&ctx, result).await?;

    Ok(())
}
