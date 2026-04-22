use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::{db::query::Query, model::Paginated};
use trustify_module_fundamental::sbom::model::SbomPackage;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
/// Issue <https://github.com/guacsec/trustify/issues/1395>: Ensure that parallel uploads
/// of the same document don't create multiple instances.
async fn ingest_10(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let mut f = vec![];
    for _ in 0..10 {
        f.push(ctx.ingest_document(
            "cyclonedx/rh/image_index_variants/example_container_variant_amd64.json",
        ));
    }

    futures_util::future::try_join_all(f).await?;

    let service = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

    let result = service
        .fetch_sboms::<_, SbomPackage>(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 0,
                total: true,
            },
            Default::default(),
            &ctx.db,
        )
        .await?;
    assert_eq!(Some(1), result.total);

    Ok(())
}
