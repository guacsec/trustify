use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

/// This is a test for issue #552 and #762, testing a SPDX reference against `NOASSERTION`.
///
/// Also see: [`trustify_module_ingestor::graph::sbom::common::relationship::RelationshipCreator::relate`].
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn no_assertion_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx.ingest_document("spdx/issue-552.json").await?;

    Ok(())
}
