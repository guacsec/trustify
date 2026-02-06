use itertools::Itertools;
use test_context::test_context;
use test_log::test;
use trustify_common::model::Paginated;
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::sbom::model::{SbomNodeReference, Which};
use trustify_module_fundamental::{
    purl::model::summary::purl::PurlSummary, sbom::service::SbomService,
};
use trustify_test_context::TrustifyContext;

fn to_string(purl: &PurlSummary) -> String {
    purl.head.purl.to_string()
}

fn to_strings(purls: &[PurlSummary]) -> Vec<String> {
    purls.iter().map(to_string).sorted_unstable().collect()
}

/// test with multiple purls
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone());

    let result = ctx
        .ingest_document("cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6_aliases.sbom.json")
        .await?;

    let sbom_id = result.id.parse().expect("Must be a UID");

    // fetch describes

    let packages = service
        .describes_packages(sbom_id, Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 1);
    assert_eq!(packages.items.len(), 1);

    let package = &packages.items[0];
    assert_eq!(
        to_strings(&package.purl),
        // we must find two purls here, one from the main section, the other from the evidence
        vec![
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&foo=bar"
        ]
    );

    // now check component

    let result = service
        .fetch_related_packages(
            sbom_id,
            Default::default(),
            Paginated::default(),
            Which::Right,
            SbomNodeReference::Package("pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src" /* this is actually the bom-ref value */),
            Some(Relationship::AncestorOf),
            &ctx.db,
        )
        .await?;

    assert_eq!(result.total, 1);
    let relation = &result.items[0];
    assert_eq!(
        to_strings(&relation.package.purl),
        // we must find two purls here, one from the main section, the other from the evidence
        vec![
            "pkg:generic/openssl@3.0.7?checksum=SHA-512:1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e&download_url=https://pkgs.devel.redhat.com/repo/openssl/openssl-3.0.7-hobbled.tar.gz/sha512/1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e/openssl-3.0.7-hobbled.tar.gz",
            "pkg:generic/openssl@3.0.7?checksum=SHA-512:1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e&download_url=https://pkgs.devel.redhat.com/repo/openssl/openssl-3.0.7-hobbled.tar.gz/sha512/1aea183b0b6650d9d5e7ba87b613bb1692c71720b0e75377b40db336b40bad780f7e8ae8dfb9f60841eeb4381f4b79c4c5043210c96e7cb51f90791b80c8285e/openssl-3.0.7-hobbled.tar.gz&foo=bar"
        ]
    );

    // done

    Ok(())
}
