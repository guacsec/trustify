use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::model::Paginated;
use trustify_module_fundamental::sbom::model::SbomPackage;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

/// test to see if we ingest the CPE from the metadata component, not having an explicit reference.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("cyclonedx/simple_cpe.json").await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let packages = service
        .describes_packages::<_, _, SbomPackage>(
            result.id.parse().expect("Must be a UID"),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, Some(1));
    assert_eq!(packages.items.len(), 1);

    let package = &packages.items[0];
    assert_eq!(package.cpe, vec!["cpe:/a:redhat:simple:0.0:*:*:*"]);

    Ok(())
}

/// test to see if we ingest the CPE from the metadata component, having an explicit reference.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("cyclonedx/simple_cpe_2.json").await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let packages = service
        .describes_packages::<_, _, SbomPackage>(
            result.id.parse().expect("Must be a UID"),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, Some(1));
    assert_eq!(packages.items.len(), 1);

    let package = &packages.items[0];
    assert_eq!(package.cpe, vec!["cpe:/a:redhat:simple:0.0:*:*:*"]);

    Ok(())
}

/// test to see if we ingest the CPE for any other component.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_comp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("cyclonedx/simple_cpe_3.json").await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let packages = service
        .describes_packages::<_, _, SbomPackage>(
            result.id.parse().expect("Must be a UID"),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, Some(1));
    assert_eq!(packages.items.len(), 1);

    let package = &packages.items[0];
    assert_eq!(package.cpe, Vec::<String>::new());

    // now fetch all

    let packages = service
        .fetch_sbom_packages(
            result.id.parse().expect("Must be a UID"),
            Default::default(),
            Paginated {
                offset: 0,
                limit: 1000,
                total: true,
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, Some(3));
    assert_eq!(packages.items.len(), 3);

    // ensure the cpe one is present

    let count = packages
        .items
        .iter()
        .filter(|p| {
            p.cpe
                .iter()
                .any(|cpe| cpe == "cpe:/a:redhat:simple:0.0:*:*:*")
        })
        .count();
    assert_eq!(count, 1);

    // done

    Ok(())
}
