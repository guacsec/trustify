#![allow(clippy::expect_used)]

use super::{prepare_ps_state_change, twice};
use test_context::test_context;
use test_log::test;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::severity::Severity;
use trustify_module_fundamental::purl::model::details::version_range::VersionRange;
use trustify_module_fundamental::{
    purl::{
        model::details::purl::{PurlStatus, StatusContext},
        service::PurlService,
    },
    vulnerability::{model::VulnerabilityHead, service::VulnerabilityService},
};
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::TrustifyContext;

/// Ensure that ingesting the same document twice, leads to the same ID.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn equal(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(ctx, |csaf| csaf, |csaf| csaf).await?;

    // no change, same result

    assert_eq!(r1.id, r2.id);

    // check info

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Default::default(), &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // done

    Ok(())
}

/// Ingest the same document, with an update on the product state.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn change_ps_num_advisories(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // the internal document ID will change, it's a new document

    assert_ne!(r1.id, r2.id);

    // check info - non-deprecated

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // check info - with-deprecated

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Deprecation::Consider, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 2);

    // done

    Ok(())
}

/// Ingest the same document twice. First having an affected, then fixed state.
#[test_context(TrustifyContext)]
#[test(tokio::test)]

async fn change_ps_list_vulns(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // the internal document ID will change, it's a new document

    assert_ne!(r1.id, r2.id);

    // check info

    let service = PurlService::new();
    let purls = service
        .purls(Default::default(), Default::default(), &ctx.db)
        .await?;

    // pkg:rpm/redhat/eap7-bouncycastle@1.76.0-4.redhat_00001.1.el9eap?arch=noarch
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

    assert_eq!(
        purl.head
            .purl
            .qualifiers
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![("arch".to_string(), "noarch".to_string())]
    );

    // get vuln by purl

    let purl = service
        .purl_by_uuid(&purl.head.uuid, Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must find something");

    assert_eq!(purl.advisories.len(), 1);
    let adv = &purl.advisories[0];

    assert_eq!(
        adv.head.identifier,
        "https://www.redhat.com/#CVE-2023-33201"
    );

    // now check the details

    assert_eq!(
        adv.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                ..Default::default()
            },
            average_severity: Severity::Medium,
            average_score: 5.3f64,
            status: "fixed".to_string(),
            context: Some(StatusContext::Cpe(
                "cpe:/a:redhat:jboss_enterprise_application_platform:7.4:*:el9:*".to_string()
            )),
            version_range: Some(VersionRange::Full {
                version_scheme_id: "rpm".into(),
                low_version: "1.76.0-4.redhat_00001.1.el9eap".into(),
                low_inclusive: true,
                high_version: "1.76.0-4.redhat_00001.1.el9eap".into(),
                high_inclusive: true
            }),
        }]
    );

    // done

    Ok(())
}

/// Ingest the same document twice. First having an affected, then fixed state.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn change_ps_list_vulns_all(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // the internal document ID will change, it's a new document

    assert_ne!(r1.id, r2.id);

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

    assert_eq!(
        purl.head
            .purl
            .qualifiers
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![("arch".to_string(), "noarch".to_string())]
    );

    // get vuln by purl

    let mut purl = service
        .purl_by_uuid(&purl.head.uuid, Deprecation::Consider, &ctx.db)
        .await?
        .expect("must find something");

    // must be 2, as we consider deprecated ones too

    assert_eq!(purl.advisories.len(), 2);
    purl.advisories
        .sort_unstable_by(|a, b| a.head.modified.cmp(&b.head.modified));
    let adv1 = &purl.advisories[0];
    let adv2 = &purl.advisories[1];

    assert_eq!(
        adv1.head.identifier,
        "https://www.redhat.com/#CVE-2023-33201"
    );
    assert_eq!(
        adv2.head.identifier,
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
                low_version: "1.76.0-4.redhat_00001.1.el9eap".into(),
                low_inclusive: true,
                high_version: "1.76.0-4.redhat_00001.1.el9eap".into(),
                high_inclusive: true
            }),
        }]
    );
    assert_eq!(
        adv2.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                ..Default::default()
            },
            average_severity: Severity::Medium,
            average_score: 5.3f64,
            status: "fixed".to_string(),
            context: Some(StatusContext::Cpe(
                "cpe:/a:redhat:jboss_enterprise_application_platform:7.4:*:el9:*".to_string()
            )),
            version_range: Some(VersionRange::Full {
                version_scheme_id: "rpm".into(),
                low_version: "1.76.0-4.redhat_00001.1.el9eap".into(),
                low_inclusive: true,
                high_version: "1.76.0-4.redhat_00001.1.el9eap".into(),
                high_inclusive: true
            }),
        }]
    );

    // done

    Ok(())
}
