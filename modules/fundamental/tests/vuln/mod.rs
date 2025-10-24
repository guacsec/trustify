#![allow(clippy::expect_used)]

use itertools::Itertools;
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_test_context::{Dataset, TrustifyContext, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn issue_1840(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_dataset(Dataset::DS3).await?;

    let service = VulnerabilityService::new();

    let result = service
        .analyze_purls(
            ["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"],
            &ctx.db,
            &ctx.db,
        )
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
