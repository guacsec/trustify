use super::{twice, update_mark_rejected};
use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::TrustifyContext;

/// Ensure that ingesting the same document twice, leads to the same ID.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn equal(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(ctx, |cve| cve, |cve| cve).await?;

    // no change, same result

    assert_eq!(r1.id, r2.id);

    // check info

    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let v = vuln
        .fetch_vulnerability("CVE-2021-32714", Default::default(), false, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // done

    Ok(())
}

/// Update a document, ensure that we get one (ignoring deprecated), or two (considering deprecated).
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn withdrawn(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(ctx, |cve| cve, update_mark_rejected).await?;

    // must be changed

    assert_ne!(r1.id, r2.id);

    // check without deprecated

    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let v = vuln
        .fetch_vulnerability("CVE-2021-32714", Deprecation::Ignore, false, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // must be withdrawn, as the update was
    assert!(v.head.withdrawn.is_some());
    assert!(v.advisories[0].head.head.withdrawn.is_some());

    // check with deprecated

    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let v = vuln
        .fetch_vulnerability("CVE-2021-32714", Deprecation::Consider, false, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 2);

    // must be withdrawn, as the update was
    assert!(v.head.withdrawn.is_some());
    // one needs to be withdrawn, the original one isn't
    assert!(v.advisories[0].head.head.withdrawn.is_none());
    assert!(v.advisories[1].head.head.withdrawn.is_some());

    // done

    Ok(())
}
