#![allow(clippy::expect_used)]

use itertools::Itertools;
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_module_ingestor::common::Deprecation;
use trustify_test_context::{Dataset, TrustifyContext, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn issue_1840(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_dataset(Dataset::DS3).await?;

    let service = VulnerabilityService::new();

    let result = service
        .analyze_purls(["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"], &ctx.db)
        .await?;

    println!("{:#?}", result);

    // check number of PURLs

    assert_eq!(result.len(), 1);

    // get expected purl

    let entry = &result["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"];

    // test for warnings (should be none)

    assert!(entry.warnings.is_empty());

    // test for vulnerability IDs

    let ids = entry
        .details
        .iter()
        .map(|vuln| &vuln.head.identifier)
        .sorted()
        .collect::<Vec<_>>();

    assert_eq!(ids, vec!["CVE-2024-28834"]);

    // now check advisories

    let vuln_entry = entry
        .details
        .iter()
        .find(|e| e.head.identifier == "CVE-2024-28834")
        .expect("must find entry");

    assert_eq!(vuln_entry.status.len(), 1);

    let status_entry = &vuln_entry.status["affected"];

    assert_eq!(status_entry.len(), 1);
    let json = serde_json::to_value(status_entry).expect("must serialize");
    assert!(
        json.contains_subset(json!([{
            "document_id": "CVE-2024-28834",
            "identifier": "https://www.redhat.com/#CVE-2024-28834",
            "modified": "2025-01-07T01:43:37Z",
            "published": "2024-03-21T00:00:00Z",
            "title": "gnutls: vulnerable to Minerva side-channel information leak",
            "scores": [
                {
                    "type": "3.1",
                    "value": 5.3,
                    "severity": "medium",
                }
            ]
        }])),
        "doesn't match: {json:#?}"
    );

    // done

    Ok(())
}

/// Backlink coverage for the `cpe_status` path (P6/P7 of the CPE-identity
/// backport): a vulnerability whose CVE record carries CPE applicability must
/// list the SBOM whose package CPE matches, on `/vulnerability/{id}` — including
/// when the match is by CPE identity (no PURL needed on the advisory side).
///
/// - CVE-2099-0001 affects openssl 0.9.8w (exact + range) → the firmware SBOM
///   (OpenSSL 0.9.8w via SPDX cpe23Type) MUST appear in the backlink (positive).
/// - CVE-2099-0003 affects openssl only in 2.0.0..3.0.0 → 0.9.8w is out of range
///   → the firmware SBOM MUST NOT appear (negative / version guard).
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn cpe_status_vulnerability_backlink(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_document("spdx/cpe23-firmware.json").await?;
    ctx.ingest_document("cve/CVE-2099-0001.json").await?;
    ctx.ingest_document("cve/CVE-2099-0003.json").await?;

    let service = VulnerabilityService::new();

    // Collect the set of SBOM names backlinked from a vulnerability's advisories.
    let backlinked_sbom_names = async |id: &str| -> Result<Vec<String>, anyhow::Error> {
        let details = service
            .fetch_vulnerability(id, Deprecation::Ignore, &ctx.db)
            .await?
            .expect("vulnerability must exist");
        Ok(details
            .advisories
            .iter()
            .flat_map(|adv| adv.sboms.iter())
            .map(|sbom| sbom.head.name.clone())
            .collect())
    };

    // Positive: 0.9.8w is within CVE-2099-0001's affected range → firmware backlinked.
    let positive = backlinked_sbom_names("CVE-2099-0001").await?;
    assert!(
        positive.iter().any(|n| n == "cpe23-firmware"),
        "CVE-2099-0001 must backlink the firmware SBOM via cpe_status, got {positive:?}"
    );

    // Negative: 0.9.8w is outside CVE-2099-0003's 2.0.0..3.0.0 range → not backlinked.
    let negative = backlinked_sbom_names("CVE-2099-0003").await?;
    assert!(
        !negative.iter().any(|n| n == "cpe23-firmware"),
        "CVE-2099-0003 (openssl 2.0.0..3.0.0) must NOT backlink openssl 0.9.8w, got {negative:?}"
    );

    Ok(())
}
