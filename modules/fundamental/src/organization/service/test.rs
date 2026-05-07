use actix_web::cookie::time::OffsetDateTime;
use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::db::query::Query;
use trustify_common::hashing::Digests;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_organizations(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.graph
        .ingest_advisory(
            "CPIC-1",
            ("source", "http://captpickles.com/"),
            &Digests::digest("CPIC-1"),
            AdvisoryInformation {
                id: "CAPT-1".to_string(),
                title: Some("CAPT-1".to_string()),
                version: None,
                issuer: Some("Capt Pickles Industrial Conglomerate".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    let service =
        crate::organization::service::OrganizationService::new(PaginationCache::for_test());

    let orgs = service
        .fetch_organizations(
            Query::default(),
            Paginated {
                total: true,
                ..Default::default()
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(Some(1), orgs.total);
    assert_eq!(1, orgs.items.len());

    Ok(())
}
