use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::cpe::Cpe;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::db::query::Query;
use trustify_common::hashing::Digests;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::product::ProductInformation;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_products(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = ctx
        .graph
        .ingest_sbom(
            ("source", "http://redhat.com/test.json"),
            &Digests::digest("RHSA-1"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    let pr = ctx
        .graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            &ctx.db,
        )
        .await?;

    let ver = pr
        .ingest_product_version("1.0.0".to_string(), Some(sbom.sbom.sbom_id), &ctx.db)
        .await?;

    let service = crate::product::service::ProductService::new(PaginationCache::for_test());

    let prods = service
        .fetch_products(
            Query::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(Some(1), prods.total);
    assert_eq!(1, prods.items.len());

    let ver_sbom = ver.get_sbom(&ctx.db).await?.expect("No sbom found");
    assert_eq!(ver_sbom.sbom.sbom_id, sbom.sbom.sbom_id);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn link_sbom_to_product(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let pr = ctx
        .graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: Some(Cpe::from_str("cpe:/a:redhat:tpa:2.0.0")?),
            },
            &ctx.db,
        )
        .await?;

    let prv = pr
        .ingest_product_version("1.0.0".to_string(), None, &ctx.db)
        .await?;

    let sbom = ctx
        .graph
        .ingest_sbom(
            ("source", "http://redhat.com/test.json"),
            &Digests::digest("RHSA-1"),
            Some("a".to_string()),
            (),
            &ctx.db,
        )
        .await?;

    let prv = sbom.link_to_product(prv, &ctx.db).await?;

    assert_eq!(
        sbom.sbom.sbom_id,
        prv.product_version.sbom_id.expect("no sbom")
    );

    let product = sbom.get_product(&ctx.db).await?.expect("No product");

    assert_eq!("Trusted Profile Analyzer", product.product.product.name);
    assert_eq!("1.0.0", product.product_version.version);
    assert_eq!(
        "tpa",
        product.product.product.cpe_key.clone().expect("no cpe")
    );
    assert_eq!(
        sbom.sbom.sbom_id,
        product.product_version.sbom_id.expect("No sbom")
    );

    let org = product
        .product
        .get_vendor(&ctx.db)
        .await?
        .expect("no organization");
    assert_eq!("Red Hat", org.organization.name);
    assert_eq!("redhat", org.organization.cpe_key.expect("no cpe"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_product(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let pr = ctx
        .graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            &ctx.db,
        )
        .await?;

    let service = crate::product::service::ProductService::new(PaginationCache::for_test());

    let prods = service
        .fetch_products(
            Query::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(Some(1), prods.total);
    assert_eq!(1, prods.items.len());

    let result = service.delete_product(pr.product.id, &ctx.db).await?;
    assert_eq!(1, result);

    let result = service.delete_product(pr.product.id, &ctx.db).await?;
    assert_eq!(0, result);

    Ok(())
}
