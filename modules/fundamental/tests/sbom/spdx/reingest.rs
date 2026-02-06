#![allow(clippy::expect_used)]

use anyhow::bail;
use sea_orm::EntityTrait;
use test_context::test_context;
use test_log::test;
use trustify_common::model::Paginated;
use trustify_entity::sbom;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn reingest(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn assert(ctx: &TrustifyContext, result: IngestResult) -> anyhow::Result<()> {
        let Ok(id) = result.id.parse() else {
            bail!("must be an id")
        };
        let sbom = ctx
            .graph
            .get_sbom_by_id(id, &ctx.db)
            .await?
            .expect("must be found");

        let service = SbomService::new(ctx.db.clone());

        let packages = service
            .describes_packages(sbom.sbom.sbom_id, Paginated::default(), &ctx.db)
            .await?;

        // check CPEs

        assert_eq!(
            packages
                .items
                .iter()
                .map(|p| p.cpe.clone())
                .collect::<Vec<Vec<_>>>(),
            vec![vec!["cpe:/a:redhat:quarkus:2.13:*:el8:*".to_string()]]
        );

        // check purls

        assert_eq!(
            packages
                .items
                .iter()
                .map(|p| p
                    .purl
                    .iter()
                    .map(|purl| purl.head.purl.to_string())
                    .collect())
                .collect::<Vec<Vec<_>>>(),
            vec![vec!["pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=pom".to_string()]]
        );

        // get product

        let product = sbom
            .get_product(&ctx.db)
            .await?
            .expect("must have a product");
        assert_eq!(product.product.product.name, "quarkus-bom");

        let products = ctx.graph.get_products(&ctx.db).await?;
        assert_eq!(products.len(), 1);

        // get orgs, expect one

        let orgs = ctx.graph.get_organizations(&ctx.db).await?;
        assert_eq!(orgs.len(), 1);

        // get all sboms, expect one

        let sboms = ctx
            .graph
            .locate_many_sboms(sbom::Entity::find(), &ctx.db)
            .await?;

        assert_eq!(sboms.len(), 1);

        // done

        Ok(())
    }

    // ingest once

    let result = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    assert(ctx, result).await?;

    // ingest second time

    let result = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    assert(ctx, result).await?;

    // done

    Ok(())
}
