#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn spdx_prod_comp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let mut result = ctx
        .ingest_documents([
            "spdx/rh/product_component/rhel-9.2-eus.spdx.json",
            "spdx/rh/product_component/openssl-3.0.7-18.el9_2.spdx.json",
        ])
        .await?;

    let _prod: Uuid = result.pop().unwrap().id.parse().expect("must have a uid");
    let _comp: Uuid = result.pop().unwrap().id.parse().expect("must have a uid");

    let _service = SbomService::new(ctx.db.clone());

    // TODO: implement when we have the tools

    Ok(())
}
