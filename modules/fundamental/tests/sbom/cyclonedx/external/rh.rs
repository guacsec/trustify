#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cdx_prod_comp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let mut result = ctx
        .ingest_documents([
            "cyclonedx/rh/product_component/example_product_quarkus.json",
            "cyclonedx/rh/product_component/example_component_quarkus.json",
        ])
        .await?;

    let _prod: Uuid = result.pop().unwrap().id.parse().expect("must have a uid");
    let _comp: Uuid = result.pop().unwrap().id.parse().expect("must have a uid");

    let _service = SbomService::new(ctx.db.clone());

    // TODO: implement when we have the tools

    Ok(())
}
