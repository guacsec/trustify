use super::*;
use crate::{advisory::model::AdvisoryHead, source_document::model::SourceDocument};
use std::{collections::HashMap, str::FromStr};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::{
    db::{pagination_cache::PaginationCache, query::q},
    hashing::Digests,
    model::Paginated,
    purl::Purl,
};
use trustify_entity::{
    advisory_vulnerability_score::{ScoreType, Severity},
    labels::Labels,
    version_scheme::VersionScheme,
};
use trustify_module_ingestor::graph::{
    Outcome,
    advisory::{
        AdvisoryContext, AdvisoryInformation,
        version::{VersionInfo, VersionSpec},
    },
    cvss::{ScoreCreator, ScoreInformation},
};
use trustify_test_context::TrustifyContext;

pub async fn ingest_sample_advisory<'a>(
    ctx: &'a TrustifyContext,
    id: &'a str,
    title: &'a str,
) -> Result<AdvisoryContext<'a>, trustify_module_ingestor::graph::error::Error> {
    ctx.graph
        .ingest_advisory(
            title,
            ("source", "http://redhat.com/"),
            &Digests::digest(title),
            AdvisoryInformation {
                id: id.to_string(),
                title: Some(title.to_string()),
                version: None,
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await
        .map(Outcome::into_inner)
}

pub async fn ingest_and_link_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let advisory = ingest_sample_advisory(ctx, "RHSA-1", "RHSA-1").await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;

    let mut creator = ScoreCreator::new(advisory_vuln.advisory.advisory.id);
    creator.add(ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H".to_string(),
        score: 9.1,
        severity: Severity::Critical,
    });
    creator.create(&ctx.db).await?;
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_and_link_advisory(ctx).await?;

    ingest_sample_advisory(ctx, "RHSA-2", "RHSA-2").await?;

    let fetch = AdvisoryService::new(ctx.db.clone(), PaginationCache::for_test());
    let fetched = fetch
        .fetch_advisories(
            q(""),
            Paginated {
                total: true,
                ..Default::default()
            },
            Default::default(),
            &ctx.db,
        )
        .await?;

    assert_eq!(fetched.total, Some(2));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn single_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digests = Digests::digest("RHSA-1");

    let advisory = ingest_sample_advisory(ctx, "RHSA-1", "RHSA-1").await?;

    let advisory_vuln: trustify_module_ingestor::graph::advisory::advisory_vulnerability::AdvisoryVulnerabilityContext<'_> = advisory
        .link_to_vulnerability("CVE-123", None,&ctx.db)
        .await?;
    let mut creator = ScoreCreator::new(advisory_vuln.advisory.advisory.id);
    creator.add(ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H".to_string(),
        score: 9.1,
        severity: Severity::Critical,
    });
    creator.create(&ctx.db).await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    ingest_sample_advisory(ctx, "RHSA-2", "RHSA-2").await?;

    let fetch = AdvisoryService::new(ctx.db.clone(), PaginationCache::for_test());
    let jenny256 = Id::sha256(&digests.sha256);
    let jenny384 = Id::sha384(&digests.sha384);
    let jenny512 = Id::sha512(&digests.sha512);
    let fetched = fetch.fetch_advisory(jenny256.clone(), &ctx.db).await?;
    let id = Id::Uuid(fetched.as_ref().unwrap().head.uuid);

    assert!(matches!(
            fetched,
            Some(AdvisoryDetails {
                head: AdvisoryHead { .. },
            source_document: SourceDocument {
                sha256,
                sha384,
                sha512,
                ..
            },
                ..
            })
        if sha256 == jenny256.to_string() && sha384 == jenny384.to_string() && sha512 == jenny512.to_string()));

    let fetched = fetch.fetch_advisory(id, &ctx.db).await?;
    assert!(matches!(
            fetched,
            Some(AdvisoryDetails {
                head: AdvisoryHead { .. },
                source_document: SourceDocument {
                    sha256,
                    sha384,
                    sha512,
                    ..
                },
                ..
            })
        if sha256 == jenny256.to_string() && sha384 == jenny384.to_string() && sha512 == jenny512.to_string()));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digests = Digests::digest("RHSA-1");

    let advisory = ingest_sample_advisory(ctx, "RHSA-1", "RHSA-1").await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;
    let mut creator = ScoreCreator::new(advisory_vuln.advisory.advisory.id);
    creator.add(ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H".to_string(),
        score: 9.1,
        severity: Severity::Critical,
    });
    creator.create(&ctx.db).await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    let fetch = AdvisoryService::new(ctx.db.clone(), PaginationCache::for_test());
    let jenny256 = Id::sha256(&digests.sha256);
    let fetched = fetch.fetch_advisory(jenny256.clone(), &ctx.db).await?;

    let fetched = fetched.expect("Advisory not found");

    assert!(fetch.delete_advisory(fetched.head.uuid, &ctx.db).await?);
    assert!(!fetch.delete_advisory(fetched.head.uuid, &ctx.db).await?);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_advisory_label(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digests = Digests::digest("RHSA-1");

    let advisory = ingest_sample_advisory(ctx, "RHSA-1", "RHSA-1").await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;
    let mut creator = ScoreCreator::new(advisory_vuln.advisory.advisory.id);
    creator.add(ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H".to_string(),
        score: 9.1,
        severity: Severity::Critical,
    });
    creator.create(&ctx.db).await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    let advisory_service = AdvisoryService::new(ctx.db.clone(), PaginationCache::for_test());
    let jenny256 = Id::sha256(&digests.sha256);

    let fetched = advisory_service
        .fetch_advisory(jenny256.clone(), &ctx.db)
        .await?;
    let id = Id::Uuid(fetched.as_ref().unwrap().head.uuid);

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    advisory_service
        .set_labels(id.clone(), new_labels, &ctx.db)
        .await?;

    let fetched_again = advisory_service.fetch_advisory(id.clone(), &ctx.db).await?;
    let advisory = fetched_again.expect("The advisory does not exist.");
    assert_eq!(
        advisory.head.labels.0,
        HashMap::from([
            ("label_1".into(), "First Label".into()),
            ("label_2".into(), "Second Label".into())
        ]),
        "Labels were not set correctly"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn update_advisory_label(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digests = Digests::digest("RHSA-1");

    let advisory = ingest_sample_advisory(ctx, "RHSA-1", "RHSA-1").await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;
    let mut creator = ScoreCreator::new(advisory_vuln.advisory.advisory.id);
    creator.add(ScoreInformation {
        vulnerability_id: "CVE-123".to_string(),
        r#type: ScoreType::V3_0,
        vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H".to_string(),
        score: 9.1,
        severity: Severity::Critical,
    });
    creator.create(&ctx.db).await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    advisory_vuln
        .ingest_package_status(
            None,
            &Purl::from_str("pkg:maven/org.apache/log4j")?,
            "fixed",
            VersionInfo {
                scheme: VersionScheme::Maven,
                spec: VersionSpec::Exact("1.2.3".to_string()),
            },
            &ctx.db,
        )
        .await?;

    let advisory_service = AdvisoryService::new(ctx.db.clone(), PaginationCache::for_test());
    let jenny256 = Id::sha256(&digests.sha256);

    let fetched = advisory_service
        .fetch_advisory(jenny256.clone(), &ctx.db)
        .await?;
    let id = Id::Uuid(fetched.as_ref().unwrap().head.uuid);

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    advisory_service
        .set_labels(id.clone(), new_labels, &ctx.db)
        .await?;

    let mut update_map = HashMap::new();
    update_map.insert("label_2".to_string(), "Label no 2".to_string());
    update_map.insert("label_3".to_string(), "Third Label".to_string());
    let update_labels = Labels(update_map);
    let update = trustify_entity::labels::Update::new();
    advisory_service
        .update_labels(id.clone(), |_| update.apply_to(update_labels))
        .await?;

    let fetched_again = advisory_service.fetch_advisory(id.clone(), &ctx.db).await?;
    //update only alters values of pre-existing keys - it won't add in an entirely new key/value pair
    assert_eq!(fetched_again.clone().unwrap().head.labels.len(), 2);
    assert_eq!(
        fetched_again.clone().unwrap().head.labels.0.get("label_2"),
        Some("Label no 2".to_string()).as_ref()
    );

    Ok(())
}
