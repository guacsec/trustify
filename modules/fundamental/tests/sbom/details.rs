use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::{db::pagination_cache::PaginationCache, id::Id};
use trustify_module_fundamental::common::model::{Score, ScoreType, ScoredVector, Severity};
use trustify_module_fundamental::purl::model::details::purl::StatusContext;
use trustify_module_fundamental::sbom::{
    model::{
        AffectedSeverity,
        details::{SbomDetails, SbomStatus},
    },
    service::SbomService,
};
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_module_ingestor::service::Format;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn sbom_details_cyclonedx_osv(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    // ingest the SBOM
    let result1 = ctx.ingest_document("cyclonedx/ghsa_test.json").await?;

    assert_eq!(
        result1.document_id,
        Some("urn:uuid:a5ddee00-4b86-498c-b7fd-b001b77479d1/1".to_string())
    );

    // ingest the advisories
    let pypi = ctx.ingest_document("osv/GHSA-45c4-8wx5-qw6w.json").await?;

    assert_eq!(pypi.document_id, Some("GHSA-45c4-8wx5-qw6w".to_string()));

    let cratesio = ctx.ingest_document("osv/GHSA-c25x-cm9x-qqgx.json").await?;

    assert_eq!(
        cratesio.document_id,
        Some("GHSA-c25x-cm9x-qqgx".to_string())
    );

    let go = ctx.ingest_document("osv/GHSA-4h4p-553m-46qh.json").await?;
    assert_eq!(go.document_id, Some("GHSA-4h4p-553m-46qh".to_string()));

    let npm = ctx.ingest_document("osv/GHSA-2ccf-ffrj-m4qw.json").await?;
    assert_eq!(npm.document_id, Some("GHSA-2ccf-ffrj-m4qw".to_string()));

    let packagist = ctx.ingest_document("osv/GHSA-3cqw-pxgr-jhrm.json").await?;
    assert_eq!(
        packagist.document_id,
        Some("GHSA-3cqw-pxgr-jhrm".to_string())
    );

    let nuget = ctx.ingest_document("osv/GHSA-rh58-r7jh-xhx3.json").await?;
    assert_eq!(nuget.document_id, Some("GHSA-rh58-r7jh-xhx3".to_string()));

    let rubygems = ctx.ingest_document("osv/GHSA-cvw2-xj8r-mjf7.json").await?;
    assert_eq!(
        rubygems.document_id,
        Some("GHSA-cvw2-xj8r-mjf7".to_string())
    );

    let hex_erlang = ctx.ingest_document("osv/GHSA-738q-mc72-2q22.json").await?;
    assert_eq!(
        hex_erlang.document_id,
        Some("GHSA-738q-mc72-2q22".to_string())
    );

    let swift = ctx.ingest_document("osv/GHSA-wc9m-r3v6-9p5h.json").await?;
    assert_eq!(swift.document_id, Some("GHSA-wc9m-r3v6-9p5h".to_string()));

    let pub_dart = ctx.ingest_document("osv/GHSA-fmj7-7gfw-64pg.json").await?;
    assert_eq!(
        pub_dart.document_id,
        Some("GHSA-fmj7-7gfw-64pg".to_string())
    );

    let maven = ctx.ingest_document("osv/GHSA-qq9f-q439-2574.json").await?;
    assert_eq!(maven.document_id, Some("GHSA-qq9f-q439-2574".to_string()));

    let maven_not_affecting = ctx.ingest_document("osv/GHSA-458h-wv48-fq75.json").await?;
    assert_eq!(
        maven_not_affecting.document_id,
        Some("GHSA-458h-wv48-fq75".to_string())
    );

    let sbom1 = sbom
        .fetch_sbom_details(Id::parse_uuid(result1.id)?, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");
    log::info!("SBOM1: {sbom1:?}");

    assert_eq!(11, sbom1.advisories.len());
    check_advisory(
        &sbom1,
        "GHSA-45c4-8wx5-qw6w",
        "CVE-2023-37276",
        &[
            sv(
                ScoreType::V3_1,
                5.3,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            ),
            sv(
                ScoreType::V4,
                6.9,
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            ),
        ],
    );
    check_advisory(
        &sbom1,
        "GHSA-c25x-cm9x-qqgx",
        "CVE-2023-28445",
        &[sv(
            ScoreType::V3_1,
            9.9,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        )],
    );
    check_advisory(
        &sbom1,
        "GHSA-4h4p-553m-46qh",
        "CVE-2024-6886",
        &[
            sv(
                ScoreType::V3_1,
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
            sv(
                ScoreType::V4,
                10.0,
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
            ),
        ],
    );
    check_advisory(
        &sbom1,
        "GHSA-2ccf-ffrj-m4qw",
        "CVE-2023-29020",
        &[sv(
            ScoreType::V3_1,
            6.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        )],
    );
    check_advisory(&sbom1, "GHSA-3cqw-pxgr-jhrm", "CVE-2009-3631", &[]);
    check_advisory(
        &sbom1,
        "GHSA-rh58-r7jh-xhx3",
        "CVE-2021-26423",
        &[sv(
            ScoreType::V3_1,
            7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )],
    );
    check_advisory(
        &sbom1,
        "GHSA-cvw2-xj8r-mjf7",
        "CVE-2019-25025",
        &[sv(
            ScoreType::V3_1,
            5.3,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        )],
    );
    check_advisory(
        &sbom1,
        "GHSA-738q-mc72-2q22",
        "CVE-2023-45312",
        &[sv(
            ScoreType::V3_1,
            8.8,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        )],
    );
    check_advisory(
        &sbom1,
        "GHSA-wc9m-r3v6-9p5h",
        "CVE-2025-0509",
        &[sv(
            ScoreType::V3_1,
            7.3,
            "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H",
        )],
    );
    check_advisory(
        &sbom1,
        "GHSA-fmj7-7gfw-64pg",
        "CVE-2024-48915",
        &[
            sv(
                ScoreType::V3_1,
                0.0,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            ),
            sv(
                ScoreType::V4,
                7.6,
                "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            ),
        ],
    );
    check_advisory(
        &sbom1,
        "GHSA-qq9f-q439-2574",
        "CVE-2024-8447",
        &[sv(
            ScoreType::V3_1,
            5.9,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )],
    );
    Ok(())
}

/// End-to-end test of the CPE-based matching path added in
/// `raw_sql::cpe_advisory_info_sql`: package-level CPEs harvested from an
/// SPDX SBOM (`sbom_node_cpe_ref`) matched against `cpe_status` rows written
/// by the CVE loader from `affected[].cpes`.
///
/// Ingests the synthetic firmware SBOM (OpenSSL 0.9.8w, BusyBox 1.19.4, and
/// a package with an unparseable/junk CPE) plus three synthetic CVE fixtures:
/// - CVE-2099-0001: affects openssl (exact `0.9.8w` + semver range) and
///   busybox (concrete-CPE-version fallback, no `versions` list).
/// - CVE-2099-0002: ADP-only, targets `denx:u-boot`, which this SBOM does not
///   contain -- must not surface any advisory here.
/// - CVE-2099-0003: affects openssl only in the `2.0.0..3.0.0` semver range,
///   which does NOT include `0.9.8w` -- the negative-match case that
///   differentiates this path from name-only `product_status` matching.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn sbom_details_cpe_matching(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    let result = ctx.ingest_document("spdx/cpe23-firmware.json").await?;

    let cve1 = ctx.ingest_document("cve/CVE-2099-0001.json").await?;
    assert_eq!(cve1.document_id, Some("CVE-2099-0001".to_string()));

    let cve2 = ctx.ingest_document("cve/CVE-2099-0002.json").await?;
    assert_eq!(cve2.document_id, Some("CVE-2099-0002".to_string()));

    let cve3 = ctx.ingest_document("cve/CVE-2099-0003.json").await?;
    assert_eq!(cve3.document_id, Some("CVE-2099-0003".to_string()));

    let details = sbom
        .fetch_sbom_details(Id::parse_uuid(result.id)?, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");
    log::info!("SBOM details: {details:?}");

    // CVE-2099-0001 must show up, with OpenSSL (via the exact version match)
    // and BusyBox (via the concrete-CPE-version fallback) as affected
    // packages.
    let advisory_1 = details
        .advisories
        .iter()
        .find(|a| a.head.document_id == "CVE-2099-0001")
        .expect("CVE-2099-0001 advisory must be present");
    assert_eq!(1, advisory_1.status.len());
    assert_eq!("affected", advisory_1.status[0].status);
    let package_names: std::collections::BTreeSet<String> = advisory_1.status[0]
        .packages
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert!(
        package_names.contains("OpenSSL"),
        "expected OpenSSL among matched packages, got {package_names:?}"
    );
    assert!(
        package_names.contains("BusyBox"),
        "expected BusyBox among matched packages, got {package_names:?}"
    );

    // CVE-2099-0002 (ADP-only, denx:u-boot) must NOT match -- this SBOM
    // contains no u-boot package.
    assert!(
        !details
            .advisories
            .iter()
            .any(|a| a.head.document_id == "CVE-2099-0002"),
        "CVE-2099-0002 (u-boot) must not match any package in this SBOM"
    );

    // CVE-2099-0003 (openssl, 2.0.0..3.0.0) must NOT match -- 0.9.8w falls
    // outside that range. This is the key false-positive guard: vendor+
    // product identity alone (as name-only product_status matching would
    // use) is not sufficient, version_matches() must also hold.
    assert!(
        !details
            .advisories
            .iter()
            .any(|a| a.head.document_id == "CVE-2099-0003"),
        "CVE-2099-0003 (openssl 2.0.0..3.0.0) must not match openssl 0.9.8w"
    );

    Ok(())
}

/// Parity test for PR-7: `batch_advisory_severity_counts` (used by the SBOM
/// list endpoint) must agree with `fetch_sbom_details` (the details
/// endpoint) once CPE-status matches are included in its `all_affected`
/// UNION. Before PR-7, this CPE-matched vulnerability was invisible to the
/// batch/list severity counts even though the details endpoint already
/// surfaced it (PR-6), a discrepancy this test guards against regressing.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn sbom_severity_counts_cpe_matching(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    let result = ctx.ingest_document("spdx/cpe23-firmware.json").await?;
    ctx.ingest_document("cve/CVE-2099-0001.json").await?;
    ctx.ingest_document("cve/CVE-2099-0002.json").await?;
    ctx.ingest_document("cve/CVE-2099-0003.json").await?;

    let sbom_id = Id::parse_uuid(result.id)?;
    let Id::Uuid(sbom_uuid) = sbom_id else {
        panic!("expected a UUID sbom id");
    };

    let details = sbom
        .fetch_sbom_details(sbom_id, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");

    // Non-zero: the details endpoint (PR-6) already showed CVE-2099-0001 as
    // affected via the CPE path (OpenSSL + BusyBox); the batch counts must
    // see it too.
    assert_eq!(
        1,
        details.advisories.len(),
        "expected exactly CVE-2099-0001 to match, got {:?}",
        details
            .advisories
            .iter()
            .map(|a| &a.head.document_id)
            .collect::<Vec<_>>()
    );

    let counts = sbom
        .batch_advisory_severity_counts(&[sbom_uuid], &ctx.db)
        .await?;
    let sbom_counts = counts
        .get(&sbom_uuid)
        .expect("severity counts must be present for this SBOM");

    // CVE-2099-0001 carries a single CVSS v3.1 CRITICAL score; the ADP-only
    // (u-boot) and version-excluded (openssl 2.0.0..3.0.0) CVEs must not
    // contribute any count.
    assert_eq!(
        1,
        sbom_counts.values().sum::<u64>(),
        "expected exactly one counted vulnerability, got {sbom_counts:?}"
    );
    assert_eq!(
        Some(&1),
        sbom_counts.get(&AffectedSeverity::Critical),
        "expected one critical-severity vulnerability, got {sbom_counts:?}"
    );

    Ok(())
}

/// End-to-end test that NVD-sourced CPE applicability drives range-based SBOM
/// matching. The whole reason for the NVD importer: NVD carries version *ranges*
/// (`versionStartIncluding`/`versionEndExcluding`) which, stored under the
/// `semver` scheme, match a component version that is neither range boundary --
/// something the sparse cvelistv5 CPE data (stored under the exact-only `generic`
/// scheme) cannot do.
///
/// NVD documents are ingested with an explicit `Format::NVD`: a bare NVD `cve`
/// object is indistinguishable from OSV by content sniffing.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn sbom_details_nvd_cpe_range_matching(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    let result = ctx.ingest_document("spdx/cpe23-firmware.json").await?;

    let hit = ctx
        .ingest_document_as("nvd/CVE-2099-2000.json", Format::NVD, ("source", "nvd"))
        .await?;
    assert_eq!(hit.document_id, Some("CVE-2099-2000".to_string()));
    let miss = ctx
        .ingest_document_as("nvd/CVE-2099-2001.json", Format::NVD, ("source", "nvd"))
        .await?;
    assert_eq!(miss.document_id, Some("CVE-2099-2001".to_string()));

    // Unbounded range: only a lower bound (`versionStartIncluding` 1.0.0, no
    // upper bound). Exercises `Version::Unbounded` on the end side; 1.19.4 >=
    // 1.0.0 so this matches.
    let unbounded_start_hit = ctx
        .ingest_document_as("nvd/CVE-2099-2002.json", Format::NVD, ("source", "nvd"))
        .await?;
    assert_eq!(
        unbounded_start_hit.document_id,
        Some("CVE-2099-2002".to_string())
    );
    // Unbounded range: only an upper bound (`versionEndExcluding` 2.0.0, no
    // lower bound). Exercises `Version::Unbounded` on the start side; 1.19.4 <
    // 2.0.0 so this matches.
    let unbounded_end_hit = ctx
        .ingest_document_as("nvd/CVE-2099-2003.json", Format::NVD, ("source", "nvd"))
        .await?;
    assert_eq!(
        unbounded_end_hit.document_id,
        Some("CVE-2099-2003".to_string())
    );
    // Inclusive lower boundary: the component version equals
    // `versionStartIncluding` (1.19.4 == 1.19.4). Must match -- catches an
    // off-by-one that treats the inclusive start as exclusive.
    let inclusive_start_hit = ctx
        .ingest_document_as("nvd/CVE-2099-2004.json", Format::NVD, ("source", "nvd"))
        .await?;
    assert_eq!(
        inclusive_start_hit.document_id,
        Some("CVE-2099-2004".to_string())
    );
    // Exclusive upper boundary: the component version equals
    // `versionEndExcluding` (1.19.4 == 1.19.4). Must NOT match -- catches an
    // off-by-one that treats the exclusive end as inclusive.
    let exclusive_end_miss = ctx
        .ingest_document_as("nvd/CVE-2099-2005.json", Format::NVD, ("source", "nvd"))
        .await?;
    assert_eq!(
        exclusive_end_miss.document_id,
        Some("CVE-2099-2005".to_string())
    );

    let details = sbom
        .fetch_sbom_details(Id::parse_uuid(result.id)?, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");
    log::info!("SBOM details: {details:?}");

    // Positive: busybox 1.19.4 falls inside [1.0.0, 2.0.0). It is neither bound,
    // so this only matches because the semver scheme does ordered range
    // comparison -- the exact-only `generic` scheme would have missed it.
    let advisory = details
        .advisories
        .iter()
        .find(|a| a.head.document_id == "CVE-2099-2000")
        .expect("CVE-2099-2000 must match busybox 1.19.4 via a semver range");
    let package_names: std::collections::BTreeSet<String> = advisory.status[0]
        .packages
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert!(
        package_names.contains("BusyBox"),
        "expected BusyBox among matched packages, got {package_names:?}"
    );

    // Negative: [2.0.0, 3.0.0) excludes 1.19.4. Vendor/product identity alone is
    // not sufficient; the version bound must exclude it.
    assert!(
        !details
            .advisories
            .iter()
            .any(|a| a.head.document_id == "CVE-2099-2001"),
        "CVE-2099-2001 (busybox 2.0.0..3.0.0) must not match busybox 1.19.4"
    );

    // Asserts that `document_id` matches busybox 1.19.4 in this SBOM, i.e. its
    // version range covers the component version.
    let matches_busybox = |document_id: &str| {
        details
            .advisories
            .iter()
            .find(|a| a.head.document_id == document_id)
            .is_some_and(|advisory| {
                advisory
                    .status
                    .iter()
                    .flat_map(|status| status.packages.iter())
                    .any(|p| p.name == "BusyBox")
            })
    };

    // Unbounded end: [1.0.0, ∞) covers 1.19.4.
    assert!(
        matches_busybox("CVE-2099-2002"),
        "CVE-2099-2002 (busybox >= 1.0.0, unbounded end) must match busybox 1.19.4"
    );
    // Unbounded start: (∞, 2.0.0) covers 1.19.4.
    assert!(
        matches_busybox("CVE-2099-2003"),
        "CVE-2099-2003 (busybox < 2.0.0, unbounded start) must match busybox 1.19.4"
    );
    // Inclusive lower bound sits exactly on the component version.
    assert!(
        matches_busybox("CVE-2099-2004"),
        "CVE-2099-2004 (busybox [1.19.4, 2.0.0)) must match busybox 1.19.4 at the inclusive lower bound"
    );
    // Exclusive upper bound sits exactly on the component version -- excluded.
    assert!(
        !details
            .advisories
            .iter()
            .any(|a| a.head.document_id == "CVE-2099-2005"),
        "CVE-2099-2005 (busybox [1.0.0, 1.19.4)) must not match busybox 1.19.4 at the exclusive upper bound"
    );

    Ok(())
}

/// Regression test for TC-5630 / TC-5171 (wrong-product / CPE-context not
/// checked), fixture `cyclonedx/TC-5630/S3_wrongproduct_hummingbird_curl`.
///
/// The SBOM describes a RHEL-8 host carrying
/// `pkg:rpm/redhat/curl@7.61.1-34.el8_10.11`. Three curl VEX documents each
/// mention two *distinct* Red Hat products that both ship curl:
/// `enterprise_linux:8` (the product this SBOM belongs to) and
/// `hummingbird:1` (Red Hat Hardened Images -- a separate product that must
/// never be attributed to this el8 SBOM).
///
/// Two failure modes are guarded:
/// - **Wrong-product attribution:** no status for the el8 curl may carry a
///   `hummingbird` context CPE. The `fixed` hummingbird rows are for a
///   different product and must not attach here.
/// - **Whole-CVE false positive (CVE-2025-10966):** el8 curl is
///   `known_not_affected`, so this CVE must not appear as `affected` at all --
///   it would only surface via the spurious hummingbird match.
///
/// CVE-2025-13034 is genuinely `known_affected` for el8 curl and must appear,
/// but only under the `enterprise_linux:8` context.
///
/// NOTE: currently `#[ignore]`d because it is a *reproducer* for an unfixed
/// case. This SBOM's describing/root node (`s3-wrongproduct-target`) carries no
/// CPE -- the `enterprise_linux:8` CPE is on the `rhel` OS component, not the
/// described node -- so `sbom_describing_cpe` is empty and the context filter
/// falls through to "unscoped SBOM matches everything", letting the hummingbird
/// product status attach to el8 curl. Remove `#[ignore]` once context scoping
/// derives product identity from the OS/root component's CPE.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
#[ignore = "TC-5630/TC-5171 reproducer: wrong-product attribution not yet fixed for SBOMs whose described node has no CPE"]
async fn sbom_details_wrong_product_cpe_context(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    const BASE: &str = "cyclonedx/TC-5630/S3_wrongproduct_hummingbird_curl";

    ctx.ingest_documents([
        format!("{BASE}/vex/CVE-2025-10966.json"),
        format!("{BASE}/vex/CVE-2025-10148.json"),
        format!("{BASE}/vex/CVE-2025-13034.json"),
    ])
    .await?;

    let result = ctx
        .ingest_document(format!("{BASE}/sbom_curl_el8.cdx.json"))
        .await?;

    let details = sbom
        .fetch_sbom_details(Id::parse_uuid(result.id)?, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");
    log::info!("SBOM details: {details:?}");

    // No status on any advisory may be attributed to the hummingbird product.
    // This is the core wrong-product invariant.
    for advisory in &details.advisories {
        for status in &advisory.status {
            if let Some(StatusContext::Cpe(cpe)) = &status.context {
                assert!(
                    !cpe.contains("hummingbird"),
                    "advisory {} vuln {} attributed to wrong product: {cpe}",
                    advisory.head.document_id,
                    status.vulnerability.identifier,
                );
            }
        }
    }

    // Helper: collect every `affected` status entry for a given CVE.
    let affected_statuses = |cve: &str| -> Vec<&SbomStatus> {
        details
            .advisories
            .iter()
            .flat_map(|a| a.status.iter())
            .filter(|s| s.vulnerability.identifier == cve && s.status == "affected")
            .collect()
    };

    // CVE-2025-10966: whole-CVE false positive. el8 curl is
    // known_not_affected; the only `affected`-producing match would be the
    // spurious hummingbird row, which must not exist.
    assert!(
        affected_statuses("CVE-2025-10966").is_empty(),
        "CVE-2025-10966 must not be affected (el8 curl is not_affected; \
         only hummingbird matched)"
    );

    // CVE-2025-13034: genuinely affected for el8 curl. It must appear, and
    // every affected status for it must carry the enterprise_linux:8 context
    // (never hummingbird, never unscoped).
    let affected_13034 = affected_statuses("CVE-2025-13034");
    assert!(
        !affected_13034.is_empty(),
        "CVE-2025-13034 must be affected for el8 curl"
    );
    for status in &affected_13034 {
        match &status.context {
            Some(StatusContext::Cpe(cpe)) => assert!(
                cpe.contains("enterprise_linux:8"),
                "CVE-2025-13034 affected under unexpected context: {cpe}"
            ),
            other => panic!("CVE-2025-13034 affected status has non-el8 context: {other:?}"),
        }
    }

    Ok(())
}

/// Regression test for TC-5630 / TC-5171 (wrong-product / CPE-context not
/// checked), fixture `cyclonedx/TC-5630/S4_wrongproduct_satellite_chardet`.
///
/// The SBOM describes a RHEL-8 host carrying
/// `pkg:rpm/redhat/python3-chardet@3.0.4-7.el8`. `python3-chardet` also ships
/// in Red Hat Satellite (a *separate* product, built `.el7sat`). The three VEX
/// documents are Satellite advisories: each `fixed` for `cpe:/a:redhat:satellite`
/// and entirely *absent* for `enterprise_linux:8`.
///
/// This is a stronger reproducer than S3 (hummingbird): because el8-OS does not
/// security-track chardet at all, the correct result is that *none* of the three
/// CVEs appear for this SBOM. Any appearance is a whole-CVE false positive
/// caused by matching the el8 package to a Satellite advisory by name, ignoring
/// the `satellite` context CPE.
///
/// NOTE: currently `#[ignore]`d because it reproduces an unfixed case, same root
/// cause as `sbom_details_wrong_product_cpe_context`: this SBOM's described node
/// carries no CPE (the `enterprise_linux:8` CPE is on the OS component), so
/// `sbom_describing_cpe` is empty and the context filter falls through to
/// "unscoped SBOM matches everything". Remove `#[ignore]` once fixed.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
#[ignore = "TC-5630/TC-5171 reproducer: wrong-product attribution not yet fixed for SBOMs whose described node has no CPE"]
async fn sbom_details_wrong_product_satellite(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    const BASE: &str = "cyclonedx/TC-5630/S4_wrongproduct_satellite_chardet";

    ctx.ingest_documents([
        format!("{BASE}/vex/CVE-2018-11751.json"),
        format!("{BASE}/vex/CVE-2018-3258.json"),
        format!("{BASE}/vex/CVE-2019-0231.json"),
    ])
    .await?;

    let result = ctx
        .ingest_document(format!("{BASE}/sbom_python3-chardet_el8.cdx.json"))
        .await?;

    let details = sbom
        .fetch_sbom_details(Id::parse_uuid(result.id)?, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");
    log::info!("SBOM details: {details:?}");

    // No status on any advisory may be attributed to the satellite product.
    for advisory in &details.advisories {
        for status in &advisory.status {
            if let Some(StatusContext::Cpe(cpe)) = &status.context {
                assert!(
                    !cpe.contains("satellite"),
                    "advisory {} vuln {} attributed to wrong product: {cpe}",
                    advisory.head.document_id,
                    status.vulnerability.identifier,
                );
            }
        }
    }

    // el8-OS chardet is absent from all three Satellite advisories, so none of
    // them may appear as `affected` for this SBOM.
    for cve in ["CVE-2018-11751", "CVE-2018-3258", "CVE-2019-0231"] {
        let affected = details
            .advisories
            .iter()
            .flat_map(|a| a.status.iter())
            .any(|s| s.vulnerability.identifier == cve && s.status == "affected");
        assert!(
            !affected,
            "{cve} must not be affected: el8-OS python3-chardet is not tracked \
             by this Satellite advisory (only satellite ships/fixes it)"
        );
    }

    Ok(())
}

/// Regression test for TC-5630: a vulnerability that matches an SBOM only
/// through a package-level CPE identity (`cpe_status`) on a component that has a
/// CPE but *no* PURL must be reported consistently across all three views.
///
/// Fixture: `cyclonedx/TC-5630/registry.access.redhat.com_hi_opentofu.json`
/// (CycloneDX 1.6) contains exactly one purl-less CPE component:
/// `os:hummingbird@20251124` -> `cpe:/a:redhat:hummingbird:1`. The synthetic
/// `CVE-2026-12151` marks `cpe:2.3:a:redhat:hummingbird:1` affected, matching
/// only through that purl-less node.
///
/// Before the fix, the SBOM list severity counts included such matches while
/// both detail endpoints silently dropped them (they required the matched node
/// to carry a `qualified_purl_id`):
/// - `cpe_advisory_info_sql` filtered `WHERE qualified_purl_id IS NOT NULL`
/// - the vulnerability backlink `cpe_status_query` INNER JOINed
///   `sbom_node_purl_ref` / `qualified_purl`.
///
/// This test asserts the three views now agree:
/// 1. `fetch_sbom_details` (the `/sbom/{id}/advisory` endpoint) lists the CVE.
/// 2. `batch_advisory_severity_counts` (the SBOM list endpoint) counts it, and
///    the two counts match.
/// 3. `fetch_vulnerability` (the `/vulnerability/{id}` endpoint) backlinks the
///    SBOM.
#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn sbom_details_purlless_cpe_node_consistency(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(PaginationCache::for_test());

    const BASE: &str = "cyclonedx/TC-5630";

    ctx.ingest_document(format!("{BASE}/CVE-2026-12151.json"))
        .await?;

    let result = ctx
        .ingest_document(format!(
            "{BASE}/registry.access.redhat.com_hi_opentofu.json"
        ))
        .await?;

    let sbom_id = Id::parse_uuid(result.id)?;
    let Id::Uuid(sbom_uuid) = sbom_id else {
        panic!("expected a UUID sbom id");
    };

    // View 1: the details/advisory endpoint must list the CPE-only match.
    let details = sbom
        .fetch_sbom_details(sbom_id, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");

    let detail_cve_present = details
        .advisories
        .iter()
        .any(|a| a.head.document_id == "CVE-2026-12151");
    assert!(
        detail_cve_present,
        "CVE-2026-12151 must appear on /sbom/{{id}}/advisory via the purl-less \
         hummingbird CPE node, got {:?}",
        details
            .advisories
            .iter()
            .map(|a| &a.head.document_id)
            .collect::<Vec<_>>()
    );

    // The matched package is the purl-less CPE node: it carries the hummingbird
    // CPE and no PURL.
    let matched_pkg = details
        .advisories
        .iter()
        .filter(|a| a.head.document_id == "CVE-2026-12151")
        .flat_map(|a| a.status.iter())
        .flat_map(|s| s.packages.iter())
        .find(|p| p.name == "hummingbird")
        .expect("hummingbird package must be the matched node");
    assert!(
        matched_pkg.purl.is_empty(),
        "matched node must have no PURL, got {:?}",
        matched_pkg.purl
    );

    // View 2: the list endpoint's severity counts must include the same match.
    let counts = sbom
        .batch_advisory_severity_counts(&[sbom_uuid], &ctx.db)
        .await?;
    let list_count: u64 = counts
        .get(&sbom_uuid)
        .map(|c| c.values().sum())
        .unwrap_or_default();

    // The details endpoint counts distinct affected advisories/CVEs; compare
    // against the list severity-count total. Both must see CVE-2026-12151.
    let detail_affected_count = details
        .advisories
        .iter()
        .filter(|a| a.status.iter().any(|s| s.status == "affected"))
        .count() as u64;

    assert_eq!(
        list_count, detail_affected_count,
        "list severity-count total ({list_count}) must equal the details \
         affected-advisory count ({detail_affected_count})"
    );
    assert!(
        list_count >= 1,
        "expected at least the CPE-only CVE to be counted, got {list_count}"
    );

    // View 3: the vulnerability detail endpoint must backlink this SBOM.
    let vuln = VulnerabilityService::new(PaginationCache::for_test());
    let vuln_details = vuln
        .fetch_vulnerability("CVE-2026-12151", Default::default(), false, &ctx.db)
        .await?
        .expect("vulnerability must exist");

    let backlinked: Vec<_> = vuln_details
        .advisories
        .iter()
        .flat_map(|a| a.sboms.iter())
        .map(|s| s.head.id)
        .collect();
    assert!(
        backlinked.contains(&sbom_uuid),
        "SBOM must be backlinked from CVE-2026-12151 via the purl-less CPE \
         node, got {backlinked:?}"
    );

    Ok(())
}

/// Constructs a `ScoredVector` from its parts, deriving the severity from the type and value.
fn sv(r#type: ScoreType, value: f64, vector: impl Into<String>) -> ScoredVector {
    ScoredVector {
        score: Score {
            severity: Severity::from((r#type, value)),
            r#type,
            value,
        },
        vector: vector.into(),
    }
}

/// Asserts that the given advisory is present in the SBOM, has a single affected status entry
/// for the expected vulnerability, and carries exactly the expected CVSS scores.
fn check_advisory(
    sbom: &SbomDetails,
    advisory_id: &str,
    vulnerability_id: &str,
    expected_scores: &[ScoredVector],
) {
    let advisories = sbom
        .advisories
        .clone()
        .into_iter()
        .filter(|advisory| advisory.head.document_id == advisory_id)
        .collect::<Vec<_>>();
    assert_eq!(
        1,
        advisories.len(),
        "Found none or too many advisories with ID {advisory_id}"
    );
    let advisory = advisories[0].clone();
    assert_eq!(1, advisory.status.len());
    assert_eq!(
        vulnerability_id,
        advisory.status[0].vulnerability.identifier
    );
    assert_eq!("affected", advisory.status[0].status);
    assert_eq!(
        expected_scores,
        advisory.status[0].scores.as_slice(),
        "scores mismatch for advisory {advisory_id}"
    );
}
