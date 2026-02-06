#![allow(clippy::expect_used)]

use anyhow::bail;
use std::future::Future;
use test_context::test_context;
use test_log::test;
use trustify_module_ingestor::model::IngestResult;
use trustify_module_ingestor::service::Format;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest_json(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    reingest(
        ctx,
        "osv/RUSTSEC-2021-0079.json",
        Format::OSV,
        |ctx, result| async move {
            assert_common(ctx, &result, "CVE-2021-32714").await?;
            Ok(())
        },
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest_json_unknown(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    reingest(
        ctx,
        "osv/RUSTSEC-2021-0079.json",
        Format::Unknown,
        |ctx, result| async move {
            assert_common(ctx, &result, "CVE-2021-32714").await?;
            Ok(())
        },
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest_yaml(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    reingest(
        ctx,
        "osv/RSEC-2023-6.yaml",
        Format::OSV,
        |ctx, result| async move {
            assert_common(ctx, &result, "CVE-2020-5238").await?;
            Ok(())
        },
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest_yaml_unknown(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    reingest(
        ctx,
        "osv/RSEC-2023-6.yaml",
        Format::Unknown,
        |ctx, result| async move {
            assert_common(ctx, &result, "CVE-2020-5238").await?;
            Ok(())
        },
    )
    .await
}

async fn reingest<'a, F, Fut>(
    ctx: &'a TrustifyContext,
    file: &'static str,
    format: Format,
    assert: F,
) -> Result<(), anyhow::Error>
where
    F: Fn(&'a TrustifyContext, IngestResult) -> Fut + 'a,
    Fut: Future<Output = anyhow::Result<()>> + 'a,
{
    // ingest once

    let result = ctx
        .ingest_document_as(file, format, ("source", "test"))
        .await?;
    assert(ctx, result).await?;

    // ingest second time

    let result = ctx
        .ingest_document_as(file, format, ("source", "test"))
        .await?;
    assert(ctx, result).await?;

    // done

    Ok(())
}

async fn assert_common(
    ctx: &TrustifyContext,
    result: &IngestResult,
    expected_vuln_id: &str,
) -> anyhow::Result<()> {
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
        expected_vuln_id
    );

    let all = ctx.graph.get_vulnerabilities(&ctx.db).await?;
    assert_eq!(all.len(), 1);

    let vuln = ctx
        .graph
        .get_vulnerability(expected_vuln_id, &ctx.db)
        .await?
        .expect("Must be found");

    assert_eq!(vuln.vulnerability.id, expected_vuln_id);

    let descriptions = vuln.descriptions("en", &ctx.db).await?;
    assert_eq!(descriptions.len(), 0);

    Ok(())
}
