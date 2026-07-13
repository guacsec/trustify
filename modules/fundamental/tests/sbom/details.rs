use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::{db::pagination_cache::PaginationCache, id::Id};
use trustify_module_fundamental::common::model::{Score, ScoreType, ScoredVector, Severity};
use trustify_module_fundamental::sbom::{
    model::{AffectedSeverity, details::SbomDetails},
    service::SbomService,
};
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
