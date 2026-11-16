#![allow(clippy::expect_used)]
// tests of the deprecated correlation results of the fundamental APIs
#![allow(deprecated)]

use itertools::Itertools;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use sea_query::Expr;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::id::Id;
use trustify_entity::{
    correlation_option::{self, CorrelationOptionKey},
    purl_status, status,
};
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_module_ingestor::service::Format;
use trustify_test_context::{Dataset, TrustifyContext, document_bytes, subset::ContainsSubset};
use uuid::Uuid;

/// Reverse of the SBOM-page CPE match: a vulnerability's details must backlink
/// the SBOMs that match it via a package CPE (not just via PURL / product_status).
/// Guards the asymmetry where an SBOM showed the vulnerability but the
/// vulnerability page listed no related SBOMs.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn vuln_related_sboms_via_cpe(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // Firmware SBOM carries busybox 1.19.4 (package CPE); the NVD advisory marks
    // busybox affected in [1.0.0, 2.0.0), which includes 1.19.4 via semver range.
    let sbom = ctx.ingest_document("spdx/cpe23-firmware.json").await?;
    ctx.ingest_document_as("nvd/CVE-2099-2000.json", Format::NVD, ("source", "nvd"))
        .await?;

    let Id::Uuid(sbom_uuid) = Id::parse_uuid(sbom.id)? else {
        panic!("expected a UUID sbom id");
    };

    let service = VulnerabilityService::new(PaginationCache::for_test());
    let details = service
        .fetch_vulnerability("CVE-2099-2000", Default::default(), false, &ctx.db)
        .await?
        .expect("vulnerability must exist");

    let sbom_ids: Vec<_> = details
        .advisories
        .iter()
        .flat_map(|a| a.sboms.iter())
        .map(|s| s.head.id)
        .collect();

    assert!(
        sbom_ids.contains(&sbom_uuid),
        "firmware SBOM must be backlinked from CVE-2099-2000 via the CPE match, got {sbom_ids:?}"
    );

    Ok(())
}

async fn backlinked_context_sboms(
    ctx: &TrustifyContext,
    advisory: &str,
) -> Result<Vec<String>, anyhow::Error> {
    ctx.ingest_document("cyclonedx/issues/cpe_context_backlink/sbom.json")
        .await?;
    ctx.ingest_document(advisory).await?;

    let details = VulnerabilityService::new(PaginationCache::for_test())
        .fetch_vulnerability("CVE-2024-99999", Default::default(), false, &ctx.db)
        .await?
        .expect("vulnerability must exist");

    Ok(details
        .advisories
        .iter()
        .flat_map(|advisory| advisory.sboms.iter())
        .map(|sbom| sbom.head.name.clone())
        .collect())
}

/// A matching product CPE context must remain visible on vulnerability backlinks.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn vuln_backlink_cpe_context_match(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sboms =
        backlinked_context_sboms(ctx, "csaf/issues/cpe_context_backlink/advisory-match.json")
            .await?;

    assert_eq!(sboms, ["widgetos"]);
    Ok(())
}

/// A product status scoped to another product major must not backlink the SBOM.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn vuln_backlink_cpe_context_mismatch(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sboms = backlinked_context_sboms(
        ctx,
        "csaf/issues/cpe_context_backlink/advisory-mismatch.json",
    )
    .await?;

    assert!(sboms.is_empty(), "unexpected related SBOMs: {sboms:?}");
    Ok(())
}

/// Match effective ranges before SBOM expansion without losing implied statuses or CPE isolation.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn vuln_backlink_effective_statuses(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut advisory: Value = serde_json::from_slice(
        &document_bytes("csaf/issues/cpe_context_backlink/advisory-match.json").await?,
    )?;
    // Red Hat enables fixed_is_first_fixed by default; this exact fix implies affected below it.
    advisory["document"]["publisher"]["namespace"] = json!("https://www.redhat.com");
    advisory["vulnerabilities"][0]["product_status"] =
        json!({"fixed": ["widgetos-9:libwidget-1.0"]});
    ctx.ingest_json(advisory).await?;

    for (name, version, cpe) in [
        ("below", "0.9", Some("cpe:/a:acme:widgetos:9.2")),
        ("fixed", "1.0", Some("cpe:/a:acme:widgetos:9.2")),
        ("above", "1.1", Some("cpe:/a:acme:widgetos:9.2")),
        ("other-stream", "0.9", Some("cpe:/a:acme:widgetos:8.1")),
        ("no-cpe", "0.9", None),
    ] {
        let mut sbom: Value = serde_json::from_slice(
            &document_bytes("cyclonedx/issues/cpe_context_backlink/sbom.json").await?,
        )?;
        sbom["serialNumber"] = json!(format!("urn:uuid:{}", Uuid::new_v4()));
        sbom["metadata"]["component"]["name"] = json!(name);
        sbom["metadata"]["component"]
            .as_object_mut()
            .expect("component is an object")
            .remove("cpe");
        if let Some(cpe) = cpe {
            sbom["metadata"]["component"]["cpe"] = json!(cpe);
        }
        sbom["components"][0]["version"] = json!(version);
        sbom["components"][0]["purl"] = json!(format!("pkg:rpm/acme/libwidget@{version}"));
        ctx.ingest_json(sbom).await?;
    }

    let service = VulnerabilityService::new(PaginationCache::for_test());
    let backlinks = async || -> anyhow::Result<Vec<(String, String, String)>> {
        let details = service
            .fetch_vulnerability("CVE-2024-99999", Default::default(), false, &ctx.db)
            .await?
            .expect("vulnerability must exist");
        let mut result = Vec::new();
        for advisory in details.advisories {
            for sbom in advisory.sboms {
                for (status, purls) in sbom.purl_statuses {
                    for purl in purls {
                        result.push((
                            sbom.head.name.clone(),
                            status.clone(),
                            purl.head.purl.to_string(),
                        ));
                    }
                }
            }
        }
        result.sort();
        Ok(result)
    };
    let fixed = (
        "fixed".to_string(),
        "fixed".to_string(),
        "pkg:rpm/acme/libwidget@1.0".to_string(),
    );
    assert_eq!(
        backlinks().await?,
        vec![
            (
                "below".to_string(),
                "affected".to_string(),
                "pkg:rpm/acme/libwidget@0.9".to_string(),
            ),
            fixed.clone(),
            (
                "no-cpe".to_string(),
                "affected".to_string(),
                "pkg:rpm/acme/libwidget@0.9".to_string(),
            ),
        ]
    );

    // Disabling the option must remove only the implied affected backlinks, immediately.
    correlation_option::Entity::delete_many()
        .filter(correlation_option::Column::Key.eq(CorrelationOptionKey::FixedIsFirstFixed))
        .exec(&ctx.db)
        .await?;
    assert_eq!(backlinks().await?, vec![fixed]);

    // Default assertions must never produce legacy backlinks, even for an exact match.
    purl_status::Entity::update_many()
        .col_expr(purl_status::Column::IsDefault, Expr::value(true))
        .filter(purl_status::Column::VulnerabilityId.eq("CVE-2024-99999"))
        .exec(&ctx.db)
        .await?;
    assert!(backlinks().await?.is_empty());

    // An explicit not_affected assertion is also excluded from backlinks.
    let not_affected = status::Entity::find()
        .filter(status::Column::Slug.eq("not_affected"))
        .one(&ctx.db)
        .await?
        .expect("not_affected status must exist");
    purl_status::Entity::update_many()
        .set(purl_status::ActiveModel {
            is_default: Set(false),
            status_id: Set(not_affected.id),
            ..Default::default()
        })
        .filter(purl_status::Column::VulnerabilityId.eq("CVE-2024-99999"))
        .exec(&ctx.db)
        .await?;
    assert!(backlinks().await?.is_empty());
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn issue_1840(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_dataset(Dataset::DS3).await?;

    let service = VulnerabilityService::new(PaginationCache::for_test());

    let result = service
        .analyze_purls_v3(
            ["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"],
            &ctx.db,
            false,
        )
        .await?;

    log::debug!("{:#?}", result);

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
        .flat_map(|vuln| &vuln.purl_statuses)
        .map(|status| status.purl_status.vulnerability.identifier.clone())
        .sorted()
        .dedup()
        .sorted()
        .collect::<Vec<_>>();

    assert_eq!(ids, vec!["CVE-2024-28834"]);

    // now check advisories

    let vuln_entry = entry
        .details
        .iter()
        .find(|e| e.purl_statuses[0].purl_status.vulnerability.identifier == "CVE-2024-28834")
        .expect("must find entry");

    let status_entries: Vec<_> = vuln_entry
        .purl_statuses
        .iter()
        .filter(|status| status.purl_status.status == "affected")
        .collect();

    assert_eq!(status_entries.len(), 4);
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
            "scores": [{"type": "3.1", "value": 5.3, "severity": "medium", "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"}],
            "status": "affected",
            "version_range": {
                "version_scheme_id": "rpm",
                "high_version": "3.7.6-23.el9_3.4",
                "high_inclusive": false,
            }
        }, {
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
            "scores": [{"type": "3.1", "value": 5.3, "severity": "medium", "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"}],
            "status": "affected",
            "version_range": {
                "version_scheme_id": "rpm",
                "high_version": "3.8.3-4.el9_4",
                "high_inclusive": false,
            }
        }])),
        "doesn't match: {json:#?}"
    );

    // done

    Ok(())
}

/// Proves that `version_matches` filtering works on the purl_status path:
/// a version ABOVE the advisory's affected range must not be reported as affected.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn version_filtering(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_dataset(Dataset::DS3).await?;

    let service = VulnerabilityService::new(PaginationCache::for_test());

    // Version BELOW the fix threshold — known affected by CVE-2024-28834
    // (3.7.6-23.el9 < 3.7.6-23.el9_3.4, the fix version)
    let affected_result = service
        .analyze_purls_v3(
            ["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"],
            &ctx.db,
            false,
        )
        .await?;

    let affected_entry = &affected_result["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"];
    let affected_count = affected_entry
        .details
        .iter()
        .flat_map(|d| &d.purl_statuses)
        .filter(|s| {
            s.purl_status.status == "affected"
                && s.purl_status.vulnerability.identifier == "CVE-2024-28834"
        })
        .count();
    assert!(
        affected_count > 0,
        "affected version must have 'affected' statuses for CVE-2024-28834"
    );

    // Version ABOVE the fix threshold — not affected
    // (3.8.3-5.el9 > 3.8.3-4.el9_4, the highest fix range, so version_matches returns false)
    let fixed_result = service
        .analyze_purls_v3(
            ["pkg:rpm/redhat/gnutls@3.8.3-5.el9?arch=aarch64"],
            &ctx.db,
            false,
        )
        .await?;

    let fixed_entry = fixed_result.get("pkg:rpm/redhat/gnutls@3.8.3-5.el9?arch=aarch64");
    let fixed_affected_count = fixed_entry
        .map(|entry| {
            entry
                .details
                .iter()
                .flat_map(|d| &d.purl_statuses)
                .filter(|s| {
                    s.purl_status.status == "affected"
                        && s.purl_status.vulnerability.identifier == "CVE-2024-28834"
                })
                .count()
        })
        .unwrap_or(0);

    assert_eq!(
        fixed_affected_count, 0,
        "fixed version must not have 'affected' statuses for CVE-2024-28834 \
         (version_matches should filter them out)"
    );

    Ok(())
}
