#![allow(clippy::expect_used)]

use super::prepare_ps_state_change;
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::severity::Severity;
use trustify_entity::labels::Labels;
use trustify_module_fundamental::advisory::model::AdvisoryHead;
use trustify_module_fundamental::common::model::{Score, ScoreType};
use trustify_module_fundamental::organization::model::{OrganizationHead, OrganizationSummary};
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
use uuid::Uuid;

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
    let adv1 = &mut purl.advisories[0];

    assert_eq!(
        adv1.head.identifier,
        "https://www.redhat.com/#CVE-2023-33201"
    );

    // now check the details

    let blank_uuid = Uuid::new_v4();

    adv1.status[0].advisory.uuid = blank_uuid;
    if let Some(issuer) = &mut adv1.status[0].advisory.issuer {
        issuer.head.id = blank_uuid;
    }

    assert_eq!(
        adv1.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                ..Default::default()
            },
            #[allow(deprecated)]
            average_severity: Severity::Medium,
            #[allow(deprecated)]
            average_score: 5.3f64,
            scores: vec![Score {
                severity: Severity::Medium,
                value: 5.3,
                r#type: ScoreType::V3_1,
            }],
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
            advisory: AdvisoryHead {
                uuid: blank_uuid,
                identifier: "https://www.redhat.com/#CVE-2023-33201".into(),
                document_id: "CVE-2023-33201".into(),
                issuer: Some(OrganizationSummary {
                    head: OrganizationHead {
                        id: blank_uuid,
                        name: "Red Hat Product Security".into(),
                        cpe_key: None,
                        website: None
                    }
                }),
                published: Some(OffsetDateTime::from_unix_timestamp(1686873600)?),
                modified: Some(OffsetDateTime::from_unix_timestamp(1696537410)?),
                withdrawn: None,
                title: Some(
                    "potential  blind LDAP injection attack using a self-signed certificate".into()
                ),
                labels: Labels::from_iter([("source", "TrustifyContext"), ("type", "csaf")])
            },
        }]
    );

    // done

    Ok(())
}
