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
    let _ = ctx
        .ingest_parallel(["csaf/cve-2023-33201.json"; 10])
        .await?;

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
