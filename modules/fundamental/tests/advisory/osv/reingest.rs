use super::{twice, update_mark_fixed_again, update_unmark_fixed};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::purl::Purl;
use trustify_cvss::cvss3::severity::Severity;
use trustify_entity::labels::Labels;
use trustify_module_fundamental::{
    advisory::model::AdvisoryHead,
    purl::{
        model::details::{purl::PurlStatus, version_range::VersionRange},
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
    let (r1, r2) = twice(ctx, |cve| cve, |cve| cve).await?;

    // no change, same result

    assert_eq!(r1.id, r2.id);

    // check info

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2020-5238", Default::default(), &ctx.db)
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
    let (r1, r2) = twice(ctx, update_unmark_fixed, update_mark_fixed_again).await?;

    // must be changed

    assert_ne!(r1.id, r2.id);

    // check without deprecated

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2020-5238", Deprecation::Ignore, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 1);

    assert_eq!(v.advisories[0].head.head.identifier, "RSEC-2023-6");

    // check with deprecated

    let vuln = VulnerabilityService::new();
    let v = vuln
        .fetch_vulnerability("CVE-2020-5238", Deprecation::Consider, &ctx.db)
        .await?
        .expect("must exist");

    assert_eq!(v.advisories.len(), 2);

    assert_eq!(v.advisories[0].head.head.identifier, "RSEC-2023-6");
    assert_eq!(v.advisories[1].head.head.identifier, "RSEC-2023-6");

    // check status

    let service = PurlService::new();
    let purls = service
        .purls(Default::default(), Default::default(), &ctx.db)
        .await?;

    let purl = purls
        .items
        .iter()
        .find(|purl| {
            purl.head.purl.name == "commonmark" && purl.head.purl.version.as_deref() == Some("1.0")
        })
        .expect("must find one");

    assert_eq!(
        purl.head.purl,
        Purl {
            ty: "cran".to_string(),
            namespace: None,
            name: "commonmark".to_string(),
            version: Some("1.0".to_string()),
            qualifiers: Default::default(),
        }
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
    let (slice1, slice2) = purl.advisories.split_at_mut(1);
    let adv1 = &mut slice1[0];
    let adv2 = &mut slice2[0];

    assert_eq!(adv1.head.identifier, "RSEC-2023-6");
    assert_eq!(adv2.head.identifier, "RSEC-2023-6");

    // now check the details

    let blank_uuid = Uuid::new_v4();

    adv1.status[0].advisory.uuid = blank_uuid;
    adv1.status[0].advisory.published = Some(
        OffsetDateTime::from_unix_timestamp(1696568400)? + time::Duration::nanoseconds(600_000_000),
    );
    adv1.status[0].advisory.modified = Some(
        OffsetDateTime::from_unix_timestamp(1697786820)? + time::Duration::nanoseconds(600_000_000),
    );

    assert_eq!(
        adv1.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2020-5238".to_string(),
                ..Default::default()
            },
            #[allow(deprecated)]
            average_severity: Severity::None,
            #[allow(deprecated)]
            average_score: 0f64,
            scores: vec![],
            status: "affected".to_string(),
            context: None,
            version_range: Some(VersionRange::Full {
                version_scheme_id: "generic".into(),
                low_version: "1.0".into(),
                low_inclusive: true,
                high_version: "1.0".into(),
                high_inclusive: true
            }),
            advisory: AdvisoryHead {
                uuid: blank_uuid,
                identifier: "RSEC-2023-6".into(),
                document_id: "RSEC-2023-6".into(),
                issuer: None,
                published: Some(
                    OffsetDateTime::from_unix_timestamp(1696568400)?
                        + time::Duration::nanoseconds(600_000_000)
                ),
                modified: Some(
                    OffsetDateTime::from_unix_timestamp(1697786820)?
                        + time::Duration::nanoseconds(600_000_000)
                ),
                withdrawn: None,
                title: Some("Denial of Service (DoS) vulnerability".into()),
                labels: Labels::from_iter([("source", "TrustifyContext"), ("type", "osv")])
            },
        }]
    );

    adv2.status[0].advisory.uuid = blank_uuid;

    assert_eq!(
        adv2.status,
        vec![PurlStatus {
            vulnerability: VulnerabilityHead {
                normative: true,
                identifier: "CVE-2020-5238".to_string(),
                ..Default::default()
            },
            #[allow(deprecated)]
            average_severity: Severity::None,
            #[allow(deprecated)]
            average_score: 0f64,
            scores: vec![],
            status: "affected".to_string(),
            context: None,
            version_range: Some(VersionRange::Full {
                version_scheme_id: "generic".into(),
                low_version: "1.0".into(),
                low_inclusive: true,
                high_version: "1.0".into(),
                high_inclusive: true
            }),
            advisory: AdvisoryHead {
                uuid: blank_uuid,
                identifier: "RSEC-2023-6".into(),
                document_id: "RSEC-2023-6".into(),
                issuer: None,
                published: Some(
                    OffsetDateTime::from_unix_timestamp(1696568400)?
                        + time::Duration::nanoseconds(600_000_000)
                ),
                modified: Some(
                    OffsetDateTime::from_unix_timestamp(1697786820)?
                        + time::Duration::nanoseconds(600_000_000)
                ),
                withdrawn: None,
                title: Some("Denial of Service (DoS) vulnerability".into()),
                labels: Labels::from_iter([("source", "TrustifyContext"), ("type", "osv")])
            },
        }]
    );

    // done

    Ok(())
}
