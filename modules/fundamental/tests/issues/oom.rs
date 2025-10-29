//! Testing the OOM issue with some large SBOMs

use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::id::Id;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[ignore = "Only works with a pre-existing database and a specific dump"]
/// This test will not fail, but running with `--test-threads=1` it will show the amount of memory
/// used, using [`TrustifyTestContext::teardown`].
async fn fetch(ctx: &TrustifyContext) -> anyhow::Result<()> {
    // this requires an imported dataset

    let service = SbomService::new(ctx.db.clone());
    // update this digest to point to a "large SBOM"
    // the following statement can be used"
    /*
    select
        e.sha256
    from
        sbom_package_purl_ref a
            join qualified_purl b on b.id = a.qualified_purl_id
            join versioned_purl c on c.id = b.versioned_purl_id
            join sbom d on d.sbom_id = a.sbom_id
            join source_document e on d.source_document_id = e.id
    where
        c.base_purl_id = (
            select a.base_purl_id
            from purl_status a
            group by a.base_purl_id
            order by count(*) desc
            limit 1
        )
    group by
        e.sha256
    order by
        count(*) desc
    limit 1;
         */
    let id =
        Id::from_str("sha256:a08f4d8723d3f2e1e12ba4a8961c6ebccfd603577d784b24576c09be8925af40")?;
    let statuses: Vec<String> = vec!["affected".to_string()];

    let result = service.fetch_sbom_details(id, statuses, &ctx.db).await?;

    assert!(
        result.is_some(),
        "We must find this in the dataset. Otherwise, it's probably a wrong dataset, or you didn't use an existing DB dump"
    );

    Ok(())
}
