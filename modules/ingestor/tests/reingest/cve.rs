#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use anyhow::bail;
use test_context::test_context;
use test_log::test;
use time::macros::datetime;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn assert(ctx: &TrustifyContext, result: IngestResult) -> anyhow::Result<()> {
        let Ok(id) = Uuid::parse_str(&result.id) else {
            bail!("must be a UUID")
        };
        let adv = ctx
            .graph
            .get_advisory_by_id(id, &ctx.db)
            .await?
            .expect("must be found");

        let mut adv_vulns = adv.vulnerabilities(&ctx.db).await?;
        assert_eq!(adv_vulns.len(), 1);
        let adv_vuln = adv_vulns.pop().unwrap();
        assert_eq!(
            adv_vuln.advisory_vulnerability.reserved_date,
            Some(datetime!(2021-05-12 0:00:00 UTC))
        );

        let vulns = ctx.graph.get_vulnerabilities(&ctx.db).await?;
        assert_eq!(vulns.len(), 1);

        let vuln = ctx
            .graph
            .get_vulnerability("CVE-2021-32714", &ctx.db)
            .await?
            .expect("Must be found");

        let descriptions = vuln.descriptions("en", &ctx.db).await?;
        assert_eq!(descriptions.len(), 1);

        Ok(())
    }

    // ingest once

    let result = ctx.ingest_document("cve/CVE-2021-32714.json").await?;
    assert(ctx, result).await?;

    // ingest second time

    let result = ctx.ingest_document("cve/CVE-2021-32714.json").await?;
    assert(ctx, result).await?;

    // done

    Ok(())
}
