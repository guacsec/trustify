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

    let status_entries: Vec<_> = vuln_entry
        .purl_statuses
        .iter()
        .filter(|status| status.status == "affected")
        .collect();

    assert_eq!(status_entries.len(), 1);
    let json = serde_json::to_value(status_entries).expect("must serialize");
    assert!(
        json.contains_subset(json!([{
            "vulnerability": {
                "normative": true,
                "identifier": "CVE-2024-28834",
                "title": "Gnutls: vulnerable to minerva side-channel information leak",
                "description": "A flaw was found in GnuTLS. The Minerva attack is a cryptographic vulnerability that exploits deterministic behavior in systems like GnuTLS, leading to side-channel leaks. In specific scenarios, such as when using the GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE flag, it can result in a noticeable step in nonce size from 513 to 512 bits, exposing a potential timing side-channel.",
                "reserved": "2024-03-11T14:43:43.973Z",
                "published": "2024-03-21T13:29:11.532Z",
                "modified": "2024-11-25T02:45:53.454Z",
                "withdrawn": null,
                "discovered": null,
                "released": null,
                "cwes": ["CWE-327"]
            },
            "average_severity": "medium",
            "average_score": 5.3,
            "status": "affected",
            "context": null,
            "version_range": {
                "version_scheme_id": "rpm",
                "right": "3.8.3-4.el9_4",
                "right_inclusive": false,
            }
        }])),
        "doesn't match: {json:#?}"
    );

    // done

    Ok(())
}
