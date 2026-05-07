use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::{db::query::Query, model::Paginated};
use trustify_module_fundamental::advisory::service::AdvisoryService;
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
/// Issue <https://github.com/guacsec/trustify/issues/1395>: Ensure that parallel uploads
/// of the same document don't create multiple instances.
async fn ingest_10(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _ = ctx
        .ingest_parallel(["csaf/cve-2023-33201.json"; 10])
        .await?;

    let service = AdvisoryService::new(ctx.db.clone(), PaginationCache::for_test());

    let result = service
        .fetch_advisories(
            Query::default(),
            Paginated {
                offset: 0,
                limit: 0,
                total: true,
            },
            Deprecation::Consider,
            &ctx.db,
        )
        .await?;
    assert_eq!(Some(1), result.total);

    Ok(())
}
