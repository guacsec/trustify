use itertools::Itertools;
use test_context::test_context;
use test_log::test;
use trustify_module_analysis::{
    config::AnalysisConfig,
    service::{AnalysisService, ComponentReference},
};
use trustify_test_context::TrustifyContext;

/// A test to see that we can handle multiple CPEs and PURLs per package/component with SPDX.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cpe_purl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx
        .ingest_document("spdx/openssl-3.0.7-18.el9_2.spdx.alias.json")
        .await?;

    let service = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());

    let result = service
        .retrieve(
            ComponentReference::Id("SPDXRef-SRPM"),
            (),
            Default::default(),
            &ctx.db,
        )
        .await?;

    // must be exactly one node, as we query by ID and only have one SBOM
    assert_eq!(result.items.len(), 1);

    let item = &result.items[0];
    assert_eq!(
        item.base
            .cpe
            .iter()
            .map(ToString::to_string)
            .sorted()
            .collect::<Vec<_>>(),
        vec![
            "cpe:/a:redhat:openssl-foo:3.0.7:*:el9:*",
            "cpe:/a:redhat:openssl:3.0.7:*:el9:*",
        ]
    );
    assert_eq!(
        item.base
            .purl
            .iter()
            .map(ToString::to_string)
            .sorted()
            .collect::<Vec<_>>(),
        vec![
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&foo=bar"
        ]
    );

    Ok(())
}
