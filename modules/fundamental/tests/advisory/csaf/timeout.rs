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
async fn timeout(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _result = ctx
        .ingest_parallel([
            "csaf/timeout/rhsa-2023_7201.json.xz",
            "csaf/timeout/rhsa-2023_7831.json.xz",
            "csaf/timeout/rhsa-2024_0041.json.xz",
            "csaf/timeout/rhsa-2024_2394.json.xz",
            "csaf/timeout/rhsa-2024_5101.json.xz",
            "csaf/timeout/rhsa-2024_5363.json.xz",
            "csaf/timeout/rhsa-2024_10771.json.xz",
            "csaf/timeout/rhsa-2025_2270.json.xz",
            "csaf/timeout/rhsa-2025_3215.json.xz",
            "csaf/timeout/rhsa-2025_3301.json.xz",
        ])
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

    assert_eq!(Some(10), result.total);

    Ok(())
}
