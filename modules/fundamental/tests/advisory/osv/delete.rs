use super::{twice, update_mark_fixed_again, update_unmark_fixed};
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
async fn fixed(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(ctx, update_unmark_fixed, update_mark_fixed_again).await?;

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
        .fetch_vulnerability("CVE-2020-5238", Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // check with deprecated, should be the same result

    let v = vuln
        .fetch_vulnerability("CVE-2020-5238", Deprecation::Consider, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // done

    Ok(())
}
