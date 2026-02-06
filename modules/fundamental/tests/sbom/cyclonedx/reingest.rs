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

        // check components by name

        assert_eq!(
            packages
                .items
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>(),
            vec!["simple".to_string()]
        );

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

    let result = ctx.ingest_document("cyclonedx/simple.json").await?;
    assert(ctx, result).await?;

    // ingest second time

    let result = ctx.ingest_document("cyclonedx/simple.json").await?;
    assert(ctx, result).await?;

    // done

    Ok(())
}
