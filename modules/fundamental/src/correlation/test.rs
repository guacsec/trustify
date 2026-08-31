use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService};

use crate::test::caller;

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

fn advisory_cves(advisories: &Value) -> Vec<String> {
    let empty = vec![];
    advisories
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .flat_map(|adv| {
            let empty = vec![];
            adv["status"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .filter_map(|s| s["identifier"].as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn assert_advisory_has_cve(advisories: &Value, cve: &str) {
    let cves = advisory_cves(advisories);
    assert!(
        cves.iter().any(|c| c == cve),
        "Expected /sbom/advisory to contain {cve}, but got: {cves:?}"
    );
}

fn assert_advisory_no_cve(advisories: &Value, cve: &str) {
    let cves = advisory_cves(advisories);
    assert!(
        !cves.iter().any(|c| c == cve),
        "Expected /sbom/advisory NOT to contain {cve}, but it was present"
    );
}

/// Collect all CVE identifiers from a `/vulnerability/analyze` response for a
/// given PURL key.
fn analyze_cves(response: &Value, purl: &str) -> Vec<String> {
    response[purl]["details"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|d| d["identifier"].as_str().map(String::from))
        .collect()
}

fn assert_analyze_has_cve(response: &Value, purl: &str, cve: &str) {
    let cves = analyze_cves(response, purl);
    assert!(
        cves.iter().any(|c| c == cve),
        "Expected /vulnerability/analyze[{purl}] to contain {cve}, but got: {cves:?}"
    );
}

fn assert_analyze_no_cve(response: &Value, purl: &str, cve: &str) {
    let cves = analyze_cves(response, purl);
    assert!(
        !cves.iter().any(|c| c == cve),
        "Expected /vulnerability/analyze[{purl}] NOT to contain {cve}, but it was present"
    );
}

/// Collect all CVE identifiers from a `/purl/{key}` response that have status
/// "affected".
fn purl_affected_cves(details: &Value) -> Vec<String> {
    let empty = vec![];
    details["advisories"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .flat_map(|adv| {
            let empty = vec![];
            adv["status"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .filter(|s| s["status"].as_str() == Some("affected"))
                .filter_map(|s| s["vulnerability"]["identifier"].as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn assert_purl_has_cve(details: &Value, cve: &str) {
    let cves = purl_affected_cves(details);
    assert!(
        cves.iter().any(|c| c == cve),
        "Expected /purl to show {cve} as affected, but got: {cves:?}"
    );
}

fn assert_purl_no_cve(details: &Value, cve: &str) {
    let cves = purl_affected_cves(details);
    assert!(
        !cves.iter().any(|c| c == cve),
        "Expected /purl NOT to show {cve} as affected, but it was present"
    );
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

async fn get_sbom_advisories(app: &impl CallService, sbom_id: &str) -> Value {
    app.call_and_read_body_json(
        TestRequest::get()
            .uri(&format!("/api/v3/sbom/urn:uuid:{sbom_id}/advisory"))
            .to_request(),
    )
    .await
}

async fn post_analyze(app: &impl CallService, purls: &[&str]) -> Value {
    app.call_and_read_body_json(
        TestRequest::post()
            .uri("/api/v3/vulnerability/analyze")
            .set_json(json!({"purls": purls}))
            .to_request(),
    )
    .await
}

async fn get_purl_details(app: &impl CallService, purl: &str) -> Value {
    app.call_and_read_body_json(
        TestRequest::get()
            .uri(&format!("/api/v3/purl/{}", urlencoding::encode(purl)))
            .to_request(),
    )
    .await
}

// ---------------------------------------------------------------------------
// Scenario helper: resolve VEX file paths (append .xz if the compressed
// version exists, otherwise use the plain .json)
// ---------------------------------------------------------------------------

fn resolve_advisory_path(relative: &str) -> String {
    let workspace: std::path::PathBuf = env!("CARGO_WORKSPACE_ROOT").into();
    let base = workspace.join("etc/test-data").join(relative);
    let xz = format!("{}.xz", base.display());
    if std::path::Path::new(&xz).exists() {
        format!("{relative}.xz")
    } else {
        relative.to_string()
    }
}

/// Ingest all advisories listed in a scenario's expected.json.
async fn ingest_scenario_advisories(
    ctx: &TrustifyContext,
    scenario: &str,
    advisories: &[&str],
) -> anyhow::Result<()> {
    let paths: Vec<String> = advisories
        .iter()
        .map(|a| resolve_advisory_path(&format!("scenarios/{scenario}/{a}")))
        .collect();
    for path in &paths {
        ctx.ingest_document(path).await?;
    }
    Ok(())
}

// ===========================================================================
// S1: Cross-stream bind-libs (TC-5640)
//
// el8 RPM matched to el9/el10 fix ranges by name — cross-major stream false
// positive. The RPM version comparator ignores dist tags (.el8 vs .el9),
// so an el8 build sorts below el9/el10 fix builds and matches their ranges.
// ===========================================================================

#[ignore = "TC-5640: cross-stream RPM version matching not yet fixed"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s1_crossstream_bind_libs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S1_crossstream_bind-libs",
        &[
            "cve/CVE-2022-0396.json",
            "cve/CVE-2023-5517.json",
            "cve/CVE-2024-4076.json",
            "vex/CVE-2022-0396.json",
            "vex/CVE-2023-5517.json",
            "vex/CVE-2024-4076.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    // --- el8.10: past the el8 fix for all 3 CVEs → not_affected ---
    {
        let sbom = ctx
            .ingest_document("scenarios/S1_crossstream_bind-libs/sbom_bind-libs_el8.10.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2022-0396");
        assert_advisory_no_cve(&adv, "CVE-2023-5517");
        assert_advisory_no_cve(&adv, "CVE-2024-4076");
    }

    // --- el8.10 with describing-CPE: same result, CPE filter engaged ---
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S1_crossstream_bind-libs/sbom_bind-libs_el8.10_describing-cpe.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2022-0396");
        assert_advisory_no_cve(&adv, "CVE-2023-5517");
        assert_advisory_no_cve(&adv, "CVE-2024-4076");
    }

    // --- el9 below-fix: affected for CVE-2022-0396 + CVE-2024-4076 ---
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S1_crossstream_bind-libs/sbom_bind-libs_el9.0_below-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2022-0396");
        assert_advisory_no_cve(&adv, "CVE-2023-5517");
        assert_advisory_has_cve(&adv, "CVE-2024-4076");
    }

    // --- el9 at-fix: CVE-2022-0396 still affected, others not ---
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S1_crossstream_bind-libs/sbom_bind-libs_el9.0_at-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2022-0396");
        assert_advisory_no_cve(&adv, "CVE-2023-5517");
        assert_advisory_no_cve(&adv, "CVE-2024-4076");
    }

    // --- el9 above-fix: same as at-fix ---
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S1_crossstream_bind-libs/sbom_bind-libs_el9.0_above-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2022-0396");
        assert_advisory_no_cve(&adv, "CVE-2023-5517");
        assert_advisory_no_cve(&adv, "CVE-2024-4076");
    }

    // --- el10: affected for CVE-2023-5517 + CVE-2024-4076 ---
    {
        let sbom = ctx
            .ingest_document("scenarios/S1_crossstream_bind-libs/sbom_bind-libs_el10.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2022-0396");
        assert_advisory_has_cve(&adv, "CVE-2023-5517");
        assert_advisory_has_cve(&adv, "CVE-2024-4076");
    }

    Ok(())
}

// ===========================================================================
// S2: Wrong-scheme golang/OCI (TC-5170)
//
// RPM version range applied to non-RPM PURL types (OCI, golang). The
// product_status path matches by package name without checking the PURL type.
// ===========================================================================

#[ignore = "TC-5170: product_status version scheme not checked"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s2_wrongscheme_golang_oci(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S2_wrongscheme_golang_oci",
        &["vex/CVE-2023-44487_golang_barename.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    // storage3 in-range → affected (correct match)
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S2_wrongscheme_golang_oci/sbom_golang_storage3_inrange.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2023-44487");
    }

    // RPM golang (wrong product context) → not_affected
    {
        let sbom = ctx
            .ingest_document("scenarios/S2_wrongscheme_golang_oci/sbom_golang_rpm.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-44487");
    }

    // RPM golang in-range → not_affected (wrong product)
    {
        let sbom = ctx
            .ingest_document("scenarios/S2_wrongscheme_golang_oci/sbom_golang_rpm_inrange.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-44487");
    }

    // OCI golang → not_affected (wrong type entirely)
    {
        let sbom = ctx
            .ingest_document("scenarios/S2_wrongscheme_golang_oci/sbom_golang_oci.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-44487");
    }

    // el8cpe in-range → not_affected (wrong product CPE)
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S2_wrongscheme_golang_oci/sbom_golang_el8cpe_inrange.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-44487");
    }

    Ok(())
}

// ===========================================================================
// S3: Wrong-product curl/hummingbird (TC-5171)
//
// RHEL-8 curl matched to hummingbird (different product) advisories by name.
// CPE context not checked on the product_status path.
// ===========================================================================

#[ignore = "TC-5171: product_status CPE context not checked"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s3_wrongproduct_hummingbird_curl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S3_wrongproduct_hummingbird_curl",
        &[
            "cve/CVE-2024-2398.json",
            "cve/CVE-2025-10148.json",
            "cve/CVE-2025-10966.json",
            "cve/CVE-2025-13034.json",
            "vex/CVE-2024-2398.json",
            "vex/CVE-2025-10148.json",
            "vex/CVE-2025-10966.json",
            "vex/CVE-2025-13034.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    // el8 curl (past fix) → only CVE-2025-13034 affected
    {
        let sbom = ctx
            .ingest_document("scenarios/S3_wrongproduct_hummingbird_curl/sbom_curl_el8.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2024-2398");
        assert_advisory_no_cve(&adv, "CVE-2025-10148");
        assert_advisory_no_cve(&adv, "CVE-2025-10966");
        assert_advisory_has_cve(&adv, "CVE-2025-13034");
    }

    // el8 curl below-fix → CVE-2024-2398 + CVE-2025-13034 affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S3_wrongproduct_hummingbird_curl/sbom_curl_el8_below-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2024-2398");
        assert_advisory_no_cve(&adv, "CVE-2025-10148");
        assert_advisory_no_cve(&adv, "CVE-2025-10966");
        assert_advisory_has_cve(&adv, "CVE-2025-13034");
    }

    // el8 curl with el8 CPE → same as el8
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S3_wrongproduct_hummingbird_curl/sbom_curl_el8_el8cpe.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2024-2398");
        assert_advisory_no_cve(&adv, "CVE-2025-10148");
        assert_advisory_no_cve(&adv, "CVE-2025-10966");
        assert_advisory_has_cve(&adv, "CVE-2025-13034");
    }

    Ok(())
}

// ===========================================================================
// S4: Wrong-product chardet/satellite (TC-5171)
//
// RHEL-8 python3-chardet matched to Red Hat Satellite advisories by name.
// Satellite is a different product; el8-OS chardet is absent from the
// vulnerability entirely → whole-CVE false positive.
// ===========================================================================

#[ignore = "TC-5171: product_status CPE context not checked"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s4_wrongproduct_satellite_chardet(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S4_wrongproduct_satellite_chardet",
        &[
            "cve/CVE-2018-11751.json",
            "cve/CVE-2018-3258.json",
            "cve/CVE-2019-0231.json",
            "vex/CVE-2018-11751.json",
            "vex/CVE-2018-3258.json",
            "vex/CVE-2019-0231.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    // el8 chardet → none affected (el8-OS absent from Satellite advisories)
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S4_wrongproduct_satellite_chardet/sbom_python3-chardet_el8.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2018-11751");
        assert_advisory_no_cve(&adv, "CVE-2018-3258");
        assert_advisory_no_cve(&adv, "CVE-2019-0231");
    }

    // el8 chardet with el8 CPE → same
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S4_wrongproduct_satellite_chardet/sbom_python3-chardet_el8_el8cpe.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2018-11751");
        assert_advisory_no_cve(&adv, "CVE-2018-3258");
        assert_advisory_no_cve(&adv, "CVE-2019-0231");
    }

    Ok(())
}

// ===========================================================================
// S5: At-fix openssl (TC-5641)
//
// Patched RPM still reported affected because the product_status path in
// /sbom/{id}/advisory skips version_matches — it matches by name only.
// ===========================================================================

#[ignore = "TC-5641: product_status path skips version_matches on /sbom/advisory"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s5_at_fix_openssl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S5_positive_baseline_openssl_el8",
        &[
            "cve/CVE-2022-4304.json",
            "cve/CVE-2023-0215.json",
            "vex/CVE-2022-4304.json",
            "vex/CVE-2023-0215.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    // below-fix → affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_below-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2022-4304");
        assert_advisory_has_cve(&adv, "CVE-2023-0215");
    }

    // at-fix → not_affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S5_positive_baseline_openssl_el8/sbom_openssl_el8_at-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2022-4304");
        assert_advisory_no_cve(&adv, "CVE-2023-0215");
    }

    Ok(())
}

// ===========================================================================
// S6: OSV baseline urllib3 (regression guard)
//
// Correct OSV/ecosystem path — the standard semver matching works. This test
// should always pass; if it breaks, the basic correlation pipeline is wrong.
// ===========================================================================

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s6_osv_baseline_urllib3(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S6_positive_baseline_osv_urllib3",
        &["osv/GHSA-g4mx-q9vg-27p4.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    // affected version → affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3_affected.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2023-45803");

        let purl = "pkg:pypi/urllib3@1.26.17";
        let analyze = post_analyze(&app, &[purl]).await;
        assert_analyze_has_cve(&analyze, purl, "CVE-2023-45803");

        let purl_details = get_purl_details(&app, purl).await;
        assert_purl_has_cve(&purl_details, "CVE-2023-45803");
    }

    // patched version → not_affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S6_positive_baseline_osv_urllib3/sbom_urllib3_patched.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-45803");

        let purl = "pkg:pypi/urllib3@1.26.18";
        let analyze = post_analyze(&app, &[purl]).await;
        assert_analyze_no_cve(&analyze, purl, "CVE-2023-45803");

        let purl_details = get_purl_details(&app, purl).await;
        assert_purl_no_cve(&purl_details, "CVE-2023-45803");
    }

    // RPM variant → not_affected (different ecosystem)
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S6_positive_baseline_osv_urllib3/sbom_python3-urllib3_rpm_el8.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-45803");
    }

    Ok(())
}

// ===========================================================================
// S7: CPE-only hummingbird node (TC-5630)
//
// An SBOM component with a CPE but no PURL. The list count includes CVEs
// matched via CPE identity, but the detail endpoint drops them because it
// requires a qualified_purl_id.
// ===========================================================================

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s7_cpe_only_hummingbird(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S7_cpeonly_node_hummingbird",
        &[
            "cve/CVE-2026-12151.json",
            "cve/CVE-2026-16730.json",
            "cve/CVE-2026-33815.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    let sbom = ctx
        .ingest_document("scenarios/S7_cpeonly_node_hummingbird/sbom_cpeonly_hummingbird.cdx.json")
        .await?;
    let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;

    assert_advisory_has_cve(&adv, "CVE-2026-12151");
    assert_advisory_has_cve(&adv, "CVE-2026-16730");
    assert_advisory_has_cve(&adv, "CVE-2026-33815");

    Ok(())
}

// ===========================================================================
// S8: Epoch mismatch openjdk (TC-5733)
//
// rpmver_cmp ignores RPM epoch. When the SBOM PURL omits ?epoch= but the
// advisory carries it, the token comparison misaligns and produces a wrong
// verdict. Both with-epoch and no-epoch should yield the same result.
// ===========================================================================

#[ignore = "TC-5733: rpmver_cmp ignores RPM epoch (latent until version_matches on affected path)"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s8_epoch_mismatch_openjdk(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S8_epoch_mismatch_openjdk",
        &[
            "cve/CVE-2026-41254.json",
            "cve/CVE-2026-46968.json",
            "cve/CVE-2026-47010.json",
            "vex/CVE-2026-41254.json",
            "vex/CVE-2026-46968.json",
            "vex/CVE-2026-47010.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    let cves = ["CVE-2026-41254", "CVE-2026-46968", "CVE-2026-47010"];

    // no-epoch SBOM → affected for all 3
    {
        let sbom = ctx
            .ingest_document("scenarios/S8_epoch_mismatch_openjdk/sbom_openjdk_no-epoch.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        for cve in &cves {
            assert_advisory_has_cve(&adv, cve);
        }
    }

    // with-epoch SBOM → same verdict: affected for all 3
    {
        let sbom = ctx
            .ingest_document("scenarios/S8_epoch_mismatch_openjdk/sbom_openjdk_with-epoch.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        for cve in &cves {
            assert_advisory_has_cve(&adv, cve);
        }
    }

    Ok(())
}

// ===========================================================================
// S9: Sub-stream openssl el8 (TC-5640)
//
// el8.2 sub-stream RPM mis-compared to el8.10 fix ranges. Same root cause
// as S1 but within the same major stream (8.2 vs 8.10).
// ===========================================================================

#[ignore = "TC-5640: sub-stream cross-matching within same RHEL major"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s9_substream_openssl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S9_substream_openssl_el8",
        &["cve/CVE-2023-0286.json", "vex/CVE-2023-0286.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    // below-fix → affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_below-fix.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2023-0286");
    }

    // patched → not_affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S9_substream_openssl_el8/sbom_openssl_el8.2_patched.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-0286");
    }

    Ok(())
}

// ===========================================================================
// S10: Describing-CPE baseline (regression guard)
//
// CPE-context filter engages when the describing CPE is on the root node.
// The child-CPE variant tests whether the filter also works when the CPE is
// on a child/OS component.
// ===========================================================================

#[ignore = "TC-5750/TC-5730: CPE-context filter and known_not_affected not fully working"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s10_describing_cpe_baseline(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S10_combined_describing_cpe",
        &[
            "cve/CVE-2022-4304.json",
            "cve/CVE-2023-45803.json",
            "cve/CVE-2024-4076.json",
            "vex/CVE-2022-4304.json",
            "vex/CVE-2024-4076.json",
            "vex/CVE-2024-6602.json",
            "osv/GHSA-g4mx-q9vg-27p4.json",
        ],
    )
    .await?;

    let app = caller(ctx).await?;

    // combined el8 SBOM: openssl + urllib3
    {
        let sbom = ctx
            .ingest_document("scenarios/S10_combined_describing_cpe/sbom_combined_el8.cdx.json")
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2022-4304");
        assert_advisory_has_cve(&adv, "CVE-2023-45803");
        assert_advisory_no_cve(&adv, "CVE-2024-4076");
    }

    // thunderbird root-CPE → CVE-2024-6602 not_affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S10_combined_describing_cpe/sbom_thunderbird_el8_root-cpe.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2024-6602");
    }

    // thunderbird child-CPE → same: CVE-2024-6602 not_affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S10_combined_describing_cpe/sbom_thunderbird_el8_child-cpe.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2024-6602");
    }

    Ok(())
}

// ===========================================================================
// S11: Bare known_affected firefox (TC-5732)
//
// A CSAF known_affected entry without a version creates no matchable row.
// Combined with the describing-CPE filter, sub-stream fixed rows are
// excluded, leaving nothing → false negative.
// ===========================================================================

#[ignore = "TC-5732: version-less known_affected produces no matchable row"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s11_bare_known_affected_firefox(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S11_bareaffected_substream_firefox",
        &["vex/CVE-2023-6135.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    // main el8 firefox → affected (genuinely vulnerable)
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S11_bareaffected_substream_firefox/sbom_firefox_main_el8.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_has_cve(&adv, "CVE-2023-6135");
    }

    // EUS 8.8 patched → not_affected
    {
        let sbom = ctx
            .ingest_document(
                "scenarios/S11_bareaffected_substream_firefox/sbom_firefox_eus8.8_patched.cdx.json",
            )
            .await?;
        let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
        assert_advisory_no_cve(&adv, "CVE-2023-6135");
    }

    Ok(())
}

// ===========================================================================
// S12: known_not_affected ignored thunderbird (TC-5730)
//
// Trustify's correlation never honours CSAF known_not_affected. The queries
// only read status='affected'; there is no suppression step. A package the
// vendor explicitly declared not vulnerable is still reported affected.
// ===========================================================================

#[ignore = "TC-5730: known_not_affected is never honored"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s12_not_affected_ignored_thunderbird(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S12_notaffected_ignored_thunderbird",
        &["vex/CVE-2024-6602.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    let sbom = ctx
        .ingest_document(
            "scenarios/S12_notaffected_ignored_thunderbird/sbom_thunderbird_el8.cdx.json",
        )
        .await?;
    let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
    assert_advisory_no_cve(&adv, "CVE-2024-6602");

    let purl = "pkg:rpm/redhat/thunderbird@115.10.1-1.el8?arch=x86_64&epoch=0&distro=rhel-8.10";
    let analyze = post_analyze(&app, &[purl]).await;
    assert_analyze_no_cve(&analyze, purl, "CVE-2024-6602");

    let purl_details = get_purl_details(&app, purl).await;
    assert_purl_no_cve(&purl_details, "CVE-2024-6602");

    Ok(())
}

// ===========================================================================
// S13: Aliasless OSV afire (TC-5731)
//
// An OSV advisory whose vulnerability has no CVE alias is ingested but links
// to zero vulnerabilities and creates no purl_status. The OSV loader gates
// all correlation on CVE-prefixed aliases.
// ===========================================================================

#[ignore = "TC-5731: OSV advisory with no CVE alias is dropped from correlation"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s13_aliasless_osv_afire(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S13_aliasless_osv_drop",
        &["osv/GHSA-3227-r97m-8j95_real-no-cve.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    let sbom = ctx
        .ingest_document("scenarios/S13_aliasless_osv_drop/sbom_afire_affected.cdx.json")
        .await?;
    let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
    assert_advisory_has_cve(&adv, "GHSA-3227-r97m-8j95");

    let purl = "pkg:cargo/afire@1.0.0";
    let analyze = post_analyze(&app, &[purl]).await;
    assert_analyze_has_cve(&analyze, purl, "GHSA-3227-r97m-8j95");

    let purl_details = get_purl_details(&app, purl).await;
    assert_purl_has_cve(&purl_details, "GHSA-3227-r97m-8j95");

    Ok(())
}

// ===========================================================================
// S14: Product-status version-filter netty (TC-5750 / TC-5751)
//
// product_status must be scoped by CPE-context, not by version-matching the
// component version vs the product stream version range.
// ===========================================================================

#[ignore = "TC-5750: product_status version-filter guard"]
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn s14_productstatus_version_filter_netty(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    ingest_scenario_advisories(
        ctx,
        "S14_productstatus_versionfilter_netty",
        &["vex/CVE-2021-37136.json"],
    )
    .await?;

    let app = caller(ctx).await?;

    let sbom = ctx
        .ingest_document(
            "scenarios/S14_productstatus_versionfilter_netty/sbom_netty_rhsso7.cdx.json",
        )
        .await?;
    let adv = get_sbom_advisories(&app, &sbom.id.to_string()).await;
    assert_advisory_has_cve(&adv, "CVE-2021-37136");

    let purl = "pkg:maven/io.netty/netty-codec-http@4.1.45.Final-redhat-00001?type=jar";
    let analyze = post_analyze(&app, &[purl]).await;
    assert_analyze_has_cve(&analyze, purl, "CVE-2021-37136");

    let purl_details = get_purl_details(&app, purl).await;
    assert_purl_has_cve(&purl_details, "CVE-2021-37136");

    Ok(())
}
