use test_context::test_context;
use test_log::test;
use tracing::instrument;
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
    let mut f = vec![];
    for _ in 0..10 {
        f.push(ctx.ingest_document("osv/GHSA-45c4-8wx5-qw6w.json"));
    }

    futures_util::future::try_join_all(f).await?;

    let service = AdvisoryService::new(ctx.db.clone());

    let result = service
        .fetch_advisories(
            Query::default(),
            Paginated::default(),
            Deprecation::Consider,
            &ctx.db,
        )
        .await?;
    assert_eq!(1, result.total);

    Ok(())
}
