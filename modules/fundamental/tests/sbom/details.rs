use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::db::pagination_cache::PaginationCache;
use trustify_common::id::Id;
use trustify_module_fundamental::common::model::{Score, ScoreType, ScoredVector, Severity};
use trustify_module_fundamental::sbom::{model::details::SbomDetails, service::SbomService};
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
#[instrument]
async fn sbom_details_cyclonedx_osv(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone(), PaginationCache::for_test());

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
