//! Synthetic TC-7577 reproduction. No customer document contents are fixtures.
#![allow(deprecated)]

use crate::{
    purl::service::PurlService, sbom::service::SbomService,
    vulnerability::service::VulnerabilityService,
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use test_context::test_context;
use trustify_common::{
    db::pagination_cache::PaginationCache,
    id::Id,
    purl::Purl,
};
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

const BROTLI: &str = "CVE-2026-111497";
const FIX: &str = "1.1.0-8.el10_2.1";
const EXPECTED: [&str; 9] = [
    BROTLI,
    "CVE-2026-92822",
    "CVE-2026-92823",
    "CVE-2026-92824",
    "CVE-2026-18739",
    "CVE-2026-18743",
    "CVE-2026-18839",
    "CVE-2024-57970",
    "CVE-2025-25724",
];

fn purl(name: &str, version: &str, distro: &str) -> String {
    format!("pkg:rpm/redhat/{name}@{version}?arch=x86_64&distro={distro}")
}

async fn assertions(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let mut document: Value =
        serde_json::from_slice(&document_bytes("csaf/cve-2023-33201.json").await?)?;
    document["document"]["tracking"]["id"] = "TC-7577-synthetic".into();
    document["document"]["title"] = "Synthetic RPM applicability regression".into();
    let mut products = vec![];
    for (id, cpe) in [
        ("rhel", "cpe:/o:redhat:enterprise_linux:10"),
        ("rhel-minor", "cpe:/o:redhat:enterprise_linux:10.2"),
        ("rhel-other", "cpe:/o:redhat:enterprise_linux:9"),
        (
            "rhel-restricted",
            "cpe:/o:redhat:enterprise_linux:10::fastdatapath",
        ),
        ("hummingbird", "cpe:/o:redhat:hummingbird:1"),
        ("upstream", "cpe:/a:libarchive:libarchive"),
    ] {
        products.push(
            json!({"name": id, "product_id": id, "product_identification_helper": {"cpe": cpe}}),
        );
    }
    let mut relationships = vec![];
    for (id, name, version, scope) in [
        ("brotli", "libbrotli", FIX, "rhel-minor"),
        ("brotli-other", "libbrotli", "1.2.1-0.1.hum1", "hummingbird"),
        ("brotli-old", "libbrotli", "2.0.0-1.el9", "rhel-other"),
        ("modulemd", "libmodulemd", "2.15.0-12.el10", "rhel"),
        (
            "modulemd-restricted",
            "libmodulemd",
            "2.15.0-12.el10",
            "rhel-restricted",
        ),
        ("popt", "popt", "1.19-8.el10", "rhel"),
        ("xml", "libxml2", "2.12.5-1.el10", "hummingbird"),
        ("archive", "libarchive", "3.7.7-11.el10_2", "upstream"),
    ] {
        products.push(json!({
            "name": name, "product_id": id,
            "product_identification_helper": {"purl": format!("pkg:rpm/redhat/{name}@{version}")}
        }));
        relationships.push(json!({
            "category": "default_component_of", "product_reference": id,
            "relates_to_product_reference": scope,
            "full_product_name": {"name": format!("{id} in {scope}"), "product_id": format!("{id}-scoped")}
        }));
    }
    document["product_tree"] =
        json!({"full_product_names": products, "relationships": relationships});
    let mut vulnerabilities = vec![
        json!({"cve": BROTLI, "product_status": {"fixed": ["brotli-scoped", "brotli-other-scoped"]}}),
        json!({"cve": "CVE-2026-77778", "product_status": {"fixed": ["brotli-old-scoped"]}}),
        json!({"cve": "CVE-2026-77777", "product_status": {"known_affected": ["xml-scoped"]}}),
        json!({"cve": "CVE-2026-77779", "product_status": {"known_affected": ["modulemd-restricted-scoped"]}}),
    ];
    for cve in &EXPECTED[1..] {
        let product = if cve.starts_with("CVE-2026-928") {
            "modulemd-scoped"
        } else if cve.starts_with("CVE-2026-") {
            "popt-scoped"
        } else {
            "archive-scoped"
        };
        vulnerabilities.push(json!({"cve": cve, "product_status": {"known_affected": [product]}}));
    }
    document["vulnerabilities"] = vulnerabilities.into();
    ctx.ingest_json(document).await?;

    // Model the two independent upstream assertions through cpe_status, not
    // through the RHEL PURL path. Reuse the ingestor's range/status encoding.
    ctx.db.execute_unprepared(r#"
        INSERT INTO cpe_status (id, advisory_id, vulnerability_id, status_id, cpe_id, version_range_id, context_cpe_id)
        SELECT gen_random_uuid(), ps.advisory_id, ps.vulnerability_id, ps.status_id, c.id, ps.version_range_id, NULL
        FROM purl_status ps JOIN cpe c ON c.vendor = 'libarchive' AND c.product = 'libarchive' AND c.version = '*'
        WHERE ps.vulnerability_id IN ('CVE-2024-57970', 'CVE-2025-25724');
        DELETE FROM purl_status WHERE vulnerability_id IN ('CVE-2024-57970', 'CVE-2025-25724');
    "#).await?;
    Ok(())
}

async fn sbom(
    ctx: &TrustifyContext,
    root: Option<&str>,
    os: bool,
    brotli: &str,
) -> anyhow::Result<Uuid> {
    let mut component = json!({"type": "container", "bom-ref": "root", "name": "synthetic-image"});
    if let Some(cpe) = root {
        component["cpe"] = cpe.into();
    }
    let mut components = vec![];
    for (name, version) in [
        ("libbrotli", brotli),
        ("libmodulemd", "2.15.0-12.el10"),
        ("popt", "1.19-8.el10"),
        ("libxml2", "2.12.5-1.el10"),
        ("libarchive", "3.7.7-11.el10_2"),
    ] {
        let mut package = json!({
            "type": "library", "bom-ref": name, "name": name, "version": version,
            "purl": purl(name, version, "rhel-10.2")
        });
        if name == "libarchive" {
            package["cpe"] = "cpe:/a:libarchive:libarchive".into();
        }
        components.push(package);
    }
    // Same base/version, different qualifiers: must not inherit the valid
    // libbrotli occurrence's match when ranges are shared across packages.
    components.push(json!({
        "type": "library", "bom-ref": "conflicting-distro", "name": "libbrotli", "version": brotli,
        "purl": purl("libbrotli", brotli, "rhel-9")
    }));
    if os {
        components.push(json!({"type": "operating-system", "name": "RHEL", "cpe": "cpe:/o:redhat:enterprise_linux:10.2"}));
    }
    Ok(ctx
        .ingest_json(json!({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
            "metadata": {"component": component}, "components": components
        }))
        .await?
        .id
        .parse()?)
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn tc7577_root_invariant_details_counts_and_backlinks(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    assertions(ctx).await?;
    let service = SbomService::new(PaginationCache::for_test());
    let mut ids = vec![];
    for (root, os) in [
        (None, true),
        (Some("cpe:/a:example:private_image:1"), true),
        (Some("cpe:/a:example:private_image:1"), false),
        // Generalizing the root's version must not prove a different edition.
        (Some("cpe:/o:redhat:enterprise_linux:10.2::baseos"), false),
    ] {
        let id = sbom(ctx, root, os, "1.1.0-8.el10_2").await?;
        ids.push(id);
        let details = service
            .fetch_sbom_details(Id::Uuid(id), vec!["affected".into()], &ctx.db)
            .await?
            .unwrap();
        let statuses = details
            .advisories
            .iter()
            .flat_map(|a| &a.status)
            .collect::<Vec<_>>();
        let actual = statuses
            .iter()
            .map(|s| s.vulnerability.identifier.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, EXPECTED.into_iter().collect(), "{details:#?}");
        assert!(
            statuses
                .iter()
                .flat_map(|s| &s.packages)
                .all(|p| p.id != "conflicting-distro")
        );
        let brotli = statuses
            .iter()
            .find(|s| s.vulnerability.identifier == BROTLI)
            .unwrap();
        assert_eq!(brotli.fixed_versions, [FIX]);
    }
    let counts = service
        .batch_advisory_severity_counts(&ids, &ctx.db)
        .await?;
    for id in &ids {
        assert_eq!(counts[id].values().sum::<u64>(), 9, "{counts:?}");
    }

    let vulnerabilities = VulnerabilityService::new(PaginationCache::for_test());
    for cve in EXPECTED {
        let details = vulnerabilities
            .fetch_vulnerability(cve, Default::default(), false, &ctx.db)
            .await?
            .unwrap();
        let linked = details
            .advisories
            .iter()
            .flat_map(|a| &a.sboms)
            .map(|s| s.head.id)
            .collect::<BTreeSet<_>>();
        let expected = ids.iter().copied().collect();
        assert_eq!(linked, expected, "{cve}: {details:#?}");
    }
    for version in [FIX, "1.1.0-8.el10_2.2"] {
        let id = sbom(ctx, None, false, version).await?;
        let counts = service
            .batch_advisory_severity_counts(&[id], &ctx.db)
            .await?;
        assert_eq!(counts[&id].values().sum::<u64>(), 8);
    }
    Ok(())
}

#[test_context(TrustifyContext)]
#[test_log::test(actix_web::test)]
async fn tc7577_standalone_purl_context_and_fix_boundary(
    ctx: &TrustifyContext,
) -> anyhow::Result<()> {
    assertions(ctx).await?;
    let service = PurlService::new(PaginationCache::for_test());
    for (version, distro, affected) in [
        ("1.1.0-8.el10_2", "rhel-10.2", true),
        (FIX, "rhel-10.2", false),
        ("1.1.0-8.el10_2.2", "rhel-10.2", false),
        ("1.1.0-8.el10_2", "rhel-9", false),
    ] {
        let purl: Purl = purl("libbrotli", version, distro).parse()?;
        ctx.graph.ingest_qualified_package(&purl, &ctx.db).await?;
        let details = service
            .purl_by_purl(&purl, Default::default(), &ctx.db)
            .await?
            .unwrap();
        let statuses = details
            .advisories
            .iter()
            .flat_map(|a| &a.status)
            .filter(|s| s.status == "affected")
            .collect::<Vec<_>>();
        assert_eq!(
            statuses
                .iter()
                .any(|s| s.vulnerability.identifier == BROTLI),
            affected,
            "{details:#?}"
        );
        assert!(
            statuses
                .iter()
                .all(|s| s.vulnerability.identifier == BROTLI)
        );
        for status in statuses {
            assert_eq!(status.fixed_versions, [FIX]);
        }
    }
    let count = ctx
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT count(*) AS count FROM sbom",
            vec![],
        ))
        .await?
        .unwrap();
    assert_eq!(
        count.try_get::<i64>("", "count")?,
        0,
        "standalone lookups must not rely on SBOM ingestion"
    );
    Ok(())
}
