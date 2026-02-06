use crate::advisory::cve::{twice, update_mark_rejected};
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::{
    advisory::service::AdvisoryService, vulnerability::service::VulnerabilityService,
};
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::TrustifyContext;

/// Update a document, ensure that we get one (ignoring deprecated), or two (considering deprecated).
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn withdrawn(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(ctx, |cve| cve, update_mark_rejected).await?;

    let vuln = VulnerabilityService::new();

    // must be changed

    assert_ne!(r1.id, r2.id);

    // now delete the newer one

    let service = AdvisoryService::new(ctx.db.clone());
    service
        .delete_advisory(r2.id.parse().expect("must be a UUID variant"), &ctx.db)
        .await?;

    // check info

    let v = vuln
        .fetch_vulnerability("CVE-2021-32714", Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // must not be withdrawn, the update was, but got deleted
    // FIXME(#868): assert!(v.head.withdrawn.is_none());
    assert!(v.advisories[0].head.head.withdrawn.is_none());

    // check with deprecated, should be the same result

    let v = vuln
        .fetch_vulnerability("CVE-2021-32714", Deprecation::Consider, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // must not be withdrawn, the update was, but got deleted
    // FIXME(#868): assert!(v.head.withdrawn.is_none());
    assert!(v.advisories[0].head.head.withdrawn.is_none());

    // done

    Ok(())
}
