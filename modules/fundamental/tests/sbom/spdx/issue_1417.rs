use anyhow::bail;
use test_context::test_context;
use test_log::test;
use trustify_common::{db::query::Query, model::Paginated};
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

/// This is a test for issue #1414, ensuring we get back unique PURLs
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn multi_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("spdx/issues/1417/ANSIBLE-AUTOMATION-PLATFORM-2.0-RHEL-8.json.xz")
        .await?;

    let Ok(id) = result.id.parse() else {
        bail!("must be an id")
    };

    let service = SbomService::new(ctx.db.clone());

    let sbom = service
        .fetch_sbom_packages(id, Query::default(), Paginated::default(), &ctx.db)
        .await?;

    // this package shows up with 4 purls, despite there being only one
    let package = sbom
        .items
        .iter()
        .find(|package| package.id == "SPDXRef-dcb1c0cd-23c6-48d6-89eb-7a8f09278c92")
        .expect("package must be present");

    assert_eq!(package.purl.len(), 1);

    Ok(())
}
