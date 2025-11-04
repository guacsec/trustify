#![allow(clippy::expect_used)]

use super::prepare_ps_state_change;
use test_context::test_context;
use test_log::test;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::severity::Severity;
use trustify_module_fundamental::purl::model::details::version_range::VersionRange;
use trustify_module_fundamental::{
    advisory::service::AdvisoryService,
    purl::{
        model::details::purl::{PurlStatus, StatusContext},
        service::PurlService,
    },
    vulnerability::{model::VulnerabilityHead, service::VulnerabilityService},
};
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::TrustifyContext;

/// Ensure that ingesting an advisory, and a change for it, then deleting the newested one, still
/// leads to a "most recent" document.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // the internal document ID will change, it's a new document

    assert_ne!(r1.id, r2.id);

    // now delete the newer one

    let service = AdvisoryService::new(ctx.db.clone());
    service
        .delete_advisory(r2.id.try_as_uid().expect("must be a UUID variant"), &ctx.db)
        .await?;

    // now test, find only one, for either ignore or consider

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Deprecation::Consider, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // done

    Ok(())
}

/// Ingest the same document twice, then deleting the latter. The fixed state should be rolled back.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn delete_check_vulns(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // the internal document ID will change, it's a new document

    assert_ne!(r1.id, r2.id);

    // now delete the newer one

    let service = AdvisoryService::new(ctx.db.clone());
    service
        .delete_advisory(r2.id.try_as_uid().expect("must be a UUID variant"), &ctx.db)
        .await?;

    // check info

    let service = PurlService::new();
    let purls = service
        .purls(Default::default(), Default::default(), &ctx.db)
        .await?;

    // pkg:rpm/redhat/eap7-bouncycastle-util@1.76.0-4.redhat_00001.1.el9eap?arch=noarch
    let purl = purls
        .items
        .iter()
        .find(|purl| {
            purl.head.purl.name == "eap7-bouncycastle-util"
                && purl.head.purl.version.as_deref() == Some("1.76.0-4.redhat_00001.1.el9eap")
        })
        .expect("must find one");

    #[allow(deprecated)]
    {
        assert_eq!(
            purl.base.purl,
            Purl {
                ty: "rpm".to_string(),
                namespace: Some("redhat".to_string()),
                name: "eap7-bouncycastle-util".to_string(),
                version: None,
                qualifiers: Default::default(),
            }
        );
    }
    assert_eq!(
        purl.head.purl.version.as_deref(),
        Some("1.76.0-4.redhat_00001.1.el9eap")
    );

    // get vuln by purl

    let mut purl = service
        .purl_by_uuid(&purl.head.uuid, Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must find something");

    // must be 1, as we deleted the latter one

    assert_eq!(purl.advisories.len(), 1);
    purl.advisories
        .sort_unstable_by(|a, b| a.head.modified.cmp(&b.head.modified));
    let adv1 = &purl.advisories[0];

    assert_eq!(
        adv1.head.identifier,
        "https://www.redhat.com/#CVE-2023-33201"
    );

    // now check the details

    assert_eq!(
        adv1.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                ..Default::default()
            },
            average_severity: Severity::Medium,
            average_score: 5.3f64,
            status: "affected".to_string(),
            context: Some(StatusContext::Cpe(
                "cpe:/a:redhat:jboss_enterprise_application_platform:7.4:*:el9:*".to_string()
            )),
            version_range: Some(VersionRange::Full {
                version_scheme_id: "rpm".into(),
                left: "1.76.0-4.redhat_00001.1.el9eap".into(),
                left_inclusive: true,
                right: "1.76.0-4.redhat_00001.1.el9eap".into(),
                right_inclusive: true
            }),
        }]
    );

    // done

    Ok(())
}
