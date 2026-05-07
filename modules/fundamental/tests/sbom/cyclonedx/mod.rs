mod corner_cases;
mod cpe;
mod external;
mod parallel;
mod purl;
mod reingest;

use super::*;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::{model::Paginated, purl::Purl};
use trustify_module_fundamental::purl::model::{PurlHead, summary::purl::PurlSummary};
use trustify_module_fundamental::sbom::model::SbomPackage;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_parse_cyclonedx(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_cyclonedx(
        ctx,
        "zookeeper-3.9.2-cyclonedx.json",
        async move |WithContext { service, sbom, .. }| {
            let described = service
                .describes_packages::<_, _, SbomPackage>(sbom.sbom.sbom_id, Paginated::default(), &ctx.db)
                .await?;

            assert_eq!(1, described.items.len());

            let package = &described.items[0];

            assert_eq!(
                package.id,
                "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar"
            );
            assert_eq!(package.name, "zookeeper");
            assert_eq!(package.version, Some("3.9.2".to_string()));
            assert_eq!(1, package.purl.len());

            assert!(matches!(
                &package.purl[0],
                PurlSummary {
                    head: PurlHead {
                        purl,
                        ..
                    },
                    ..
                }
             if *purl == Purl::from_str( "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar")?));

            assert!(package.cpe.is_empty());

            /*
            assert_eq!(
                described.items,
                vec![SbomPackage {
                    id: "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string(),
                    name: "zookeeper".to_string(),
                    version: Some("3.9.2".to_string()),
                    purl: vec![SbomPackagePurl::String(
                        "pkg:maven/org.apache.zookeeper/zookeeper@3.9.2?type=jar".to_string()
                    )],
                    cpe: vec![],
                }]
            );

             */

            let packages = service
                .fetch_sbom_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Paginated {
                        offset: 0,
                        limit: 1,
                        total: true,
                    },
                    &ctx.db,
                )
                .await?;

            log::debug!("{packages:?}");

            assert_eq!(Some(41), packages.total);

            Ok(())
        },
    )
        .await
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn parse_cyclonedx_1dot6(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    test_with_cyclonedx(
        ctx,
        "cyclonedx/simple_1dot6.json",
        async move |WithContext { service, sbom, .. }| {
            let described = service
                .describes_packages::<_, _, SbomPackage>(
                    sbom.sbom.sbom_id,
                    Paginated::default(),
                    &ctx.db,
                )
                .await?;

            assert_eq!(1, described.items.len());

            let package = &described.items[0];

            assert_eq!(package.name, "simple");
            assert_eq!(package.version, None);
            assert_eq!(0, package.purl.len());

            assert!(package.cpe.is_empty());

            let packages = service
                .fetch_sbom_packages(
                    sbom.sbom.sbom_id,
                    Default::default(),
                    Paginated {
                        offset: 0,
                        limit: 1,
                        total: true,
                    },
                    &ctx.db,
                )
                .await?;

            log::debug!("{packages:?}");

            assert_eq!(Some(9), packages.total);

            assert_eq!(sbom.sbom.authors, vec!["Some Author".to_string()]);
            assert_eq!(sbom.sbom.suppliers, vec!["Some Supplier".to_string()]);

            Ok(())
        },
    )
    .await
}

#[instrument(skip(ctx, f))]
pub async fn test_with_cyclonedx<F>(ctx: &TrustifyContext, sbom: &str, f: F) -> anyhow::Result<()>
where
    F: AsyncFnOnce(WithContext) -> anyhow::Result<()>,
{
    test_with(
        ctx,
        sbom,
        |data| {
            Ok(serde_json::from_slice::<
                serde_cyclonedx::cyclonedx::v_1_6::CycloneDx,
            >(data)?)
        },
        async move |ctx, sbom, tx| {
            Ok(ctx
                .ingest_cyclonedx(Box::new(sbom.clone()), &Discard, tx)
                .await?)
        },
        |sbom| sbom::cyclonedx::Information(sbom).into(),
        f,
    )
    .await
}
