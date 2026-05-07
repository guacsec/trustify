#![allow(clippy::expect_used)]

use super::{prepare_ps_state_change, twice};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::model::Limit;
use trustify_common::purl::Purl;
use trustify_entity::labels::Labels;
use trustify_module_fundamental::advisory::model::AdvisoryHead;
use trustify_module_fundamental::common::model::ScoreType;
use trustify_module_fundamental::common::model::Severity;
use trustify_module_fundamental::common::model::{Score, ScoredVector};
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
use uuid::Uuid;

/// Ensure that ingesting the same document twice, leads to the same ID.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn equal(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = twice(ctx, |csaf| csaf, |csaf| csaf).await?;

    // no change, same result

    assert_eq!(r1.id, r2.id);

    // check info

    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Default::default(), false, &ctx.db)
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

    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Deprecation::Ignore, false, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    // check info - with-deprecated

    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let v = vuln
        .fetch_vulnerability("CVE-2023-33201", Deprecation::Consider, false, &ctx.db)
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

    let service = PurlService::new(PaginationCache::for_test());
    let purls = service
        .purls(
            Default::default(),
            // high limit to find the specific purl among all entries
            Limit(1000),
            &ctx.db,
        )
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

    let mut purl = service
        .purl_by_uuid(&purl.head.uuid, Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must find something");

    assert_eq!(purl.advisories.len(), 1);
    let adv = &mut purl.advisories[0];

    assert_eq!(
        adv.head.identifier,
        "https://www.redhat.com/#CVE-2023-33201"
    );

    // now check the details

    let blank_uuid = Uuid::new_v4();

    adv.status[0].advisory.uuid = blank_uuid;
    if let Some(issuer) = &mut adv.status[0].advisory.issuer {
        issuer.head.id = blank_uuid;
    }

    assert_eq!(
        adv.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                ..Default::default()
            },
            scores: vec![
                ScoredVector {
                    score: Score {
                        severity: Severity::Medium,
                        value: 5.3,
                        r#type: ScoreType::V3_1,
                    },
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                },
                ScoredVector {
                    score: Score {
                        severity: Severity::Medium,
                        value: 5.3,
                        r#type: ScoreType::V3_1,
                    },
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                }
            ],
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
            advisory: AdvisoryHead {
                uuid: blank_uuid,
                identifier: "https://www.redhat.com/#CVE-2023-33201".into(),
                document_id: "CVE-2023-33201".into(),
                issuer: Some(
                    trustify_module_fundamental::organization::model::OrganizationSummary {
                        head: trustify_module_fundamental::organization::model::OrganizationHead {
                            id: blank_uuid,
                            name: "Red Hat Product Security".into(),
                            cpe_key: None,
                            website: None
                        }
                    }
                ),
                published: Some(OffsetDateTime::from_unix_timestamp(1686873600)?),
                modified: Some(OffsetDateTime::from_unix_timestamp(1696623810)?),
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

/// Ingest the same document twice. First having an affected, then fixed state.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn change_ps_list_vulns_all(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let (r1, r2) = prepare_ps_state_change(ctx).await?;

    // the internal document ID will change, it's a new document

    assert_ne!(r1.id, r2.id);

    // check info

    let service = PurlService::new(PaginationCache::for_test());
    let purls = service
        .purls(
            Default::default(),
            // high limit to find the specific purl among all entries
            Limit(1000),
            &ctx.db,
        )
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
    purl.advisories.sort_unstable_by_key(|a| a.head.modified);
    let (slice1, slice2) = purl.advisories.split_at_mut(1);
    let adv1 = &mut slice1[0];
    let adv2 = &mut slice2[0];

    assert_eq!(
        adv1.head.identifier,
        "https://www.redhat.com/#CVE-2023-33201"
    );
    assert_eq!(
        adv2.head.identifier,
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
            scores: vec![
                ScoredVector {
                    score: Score {
                        severity: Severity::Medium,
                        value: 5.3,
                        r#type: ScoreType::V3_1,
                    },
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                },
                ScoredVector {
                    score: Score {
                        severity: Severity::Medium,
                        value: 5.3,
                        r#type: ScoreType::V3_1,
                    },
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                }
            ],
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
                issuer: Some(
                    trustify_module_fundamental::organization::model::OrganizationSummary {
                        head: trustify_module_fundamental::organization::model::OrganizationHead {
                            id: blank_uuid,
                            name: "Red Hat Product Security".into(),
                            cpe_key: None,
                            website: None
                        }
                    }
                ),
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

    adv2.status[0].advisory.uuid = blank_uuid;
    if let Some(issuer) = &mut adv2.status[0].advisory.issuer {
        issuer.head.id = blank_uuid;
    }

    assert_eq!(
        adv2.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2023-33201".to_string(),
                ..Default::default()
            },
            scores: vec![
                ScoredVector {
                    score: Score {
                        severity: Severity::Medium,
                        value: 5.3,
                        r#type: ScoreType::V3_1
                    },
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                },
                ScoredVector {
                    score: Score {
                        severity: Severity::Medium,
                        value: 5.3,
                        r#type: ScoreType::V3_1
                    },
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
                }
            ],
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
            advisory: AdvisoryHead {
                uuid: blank_uuid,
                identifier: "https://www.redhat.com/#CVE-2023-33201".into(),
                document_id: "CVE-2023-33201".into(),
                issuer: Some(
                    trustify_module_fundamental::organization::model::OrganizationSummary {
                        head: trustify_module_fundamental::organization::model::OrganizationHead {
                            id: blank_uuid,
                            name: "Red Hat Product Security".into(),
                            cpe_key: None,
                            website: None
                        }
                    }
                ),
                published: Some(OffsetDateTime::from_unix_timestamp(1686873600)?),
                modified: Some(OffsetDateTime::from_unix_timestamp(1696623810)?),
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
