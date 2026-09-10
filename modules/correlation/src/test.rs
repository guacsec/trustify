use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    collector::VecCollector,
    memory::InMemoryEngine,
    types::{ScenarioExpected, Status},
};

const SCENARIO_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../etc/test-data/scenarios");

fn load_json(path: &Path) -> serde_json::Value {
    // Try .xz first if the plain file doesn't exist
    if !path.exists() {
        let xz_path = PathBuf::from(format!("{}.xz", path.display()));
        if xz_path.exists() {
            let compressed = fs::read(&xz_path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", xz_path.display()));
            let mut json_bytes = Vec::new();
            lzma_rs::xz_decompress(&mut std::io::Cursor::new(&compressed), &mut json_bytes)
                .unwrap_or_else(|e| panic!("failed to decompress {}: {e}", xz_path.display()));
            return serde_json::from_slice(&json_bytes).unwrap_or_else(|e| {
                panic!("failed to parse JSON from {}: {e}", xz_path.display())
            });
        }
        panic!("file not found: {} (also tried .xz)", path.display());
    }
    let data = fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_slice(&data)
        .unwrap_or_else(|e| panic!("failed to parse JSON from {}: {e}", path.display()))
}

fn run_scenario(scenario_name: &str) {
    run_scenario_formats(scenario_name, &["cdx", "spdx"]);
}

fn run_scenario_format(scenario_name: &str, format: &str) {
    run_scenario_formats(scenario_name, &[format]);
}

fn run_scenario_formats(scenario_name: &str, formats: &[&str]) {
    let dir = PathBuf::from(SCENARIO_DIR).join(scenario_name);
    let expected: ScenarioExpected = {
        let data = fs::read(dir.join("expected.json"))
            .unwrap_or_else(|e| panic!("failed to read expected.json for {scenario_name}: {e}"));
        serde_json::from_slice(&data)
            .unwrap_or_else(|e| panic!("failed to parse expected.json for {scenario_name}: {e}"))
    };

    let mut engine = InMemoryEngine::new();

    for advisory_path in &expected.advisories {
        let full_path = dir.join(advisory_path);
        let json = load_json(&full_path);
        engine.load_advisory(advisory_path, &json);
    }

    // Test each SBOM in requested formats
    for (sbom_name, expectation) in &expected.sboms {
        for format in formats {
            let sbom_file = dir.join(format!("{sbom_name}.{format}.json"));
            if !sbom_file.exists() {
                continue;
            }

            let sbom_json = load_json(&sbom_file);
            let mut collector = VecCollector::default();
            let sbom = engine.load_and_correlate_sbom(sbom_name, &sbom_json, &mut collector);
            assert!(
                sbom.is_some(),
                "{scenario_name}/{sbom_name}.{format}: failed to parse SBOM"
            );

            // Build verdict map: CVE → resolved status
            let mut verdict_map: HashMap<String, Status> = HashMap::new();
            for verdict in &collector.verdicts {
                // If multiple verdicts for same CVE, resolution wins
                let existing = verdict_map.get(&verdict.vulnerability_id);
                let dominated = matches!(existing, Some(s) if s.resolves_affected());
                if !dominated {
                    verdict_map.insert(verdict.vulnerability_id.clone(), verdict.status);
                }
            }

            for (cve_id, expected_status_str) in &expectation.correct {
                let expected_status = match expected_status_str.as_str() {
                    "affected" => Some(Status::Affected),
                    "not_affected" => Some(Status::NotAffected),
                    "fixed" => Some(Status::Fixed),
                    "none" => None,
                    other => panic!("unknown expected status: {other}"),
                };

                let actual = verdict_map.get(cve_id.as_str());
                match (expected_status, actual) {
                    (None, None) => {}
                    (None, Some(actual_status)) => {
                        panic!(
                            "{scenario_name}/{sbom_name}.{format}: {cve_id}: \
                             expected no verdict, got {}",
                            actual_status.as_str()
                        );
                    }
                    (Some(expected), Some(actual_status)) => {
                        let ok = match expected {
                            Status::NotAffected => actual_status.resolves_affected(),
                            _ => *actual_status == expected,
                        };
                        assert!(
                            ok,
                            "{scenario_name}/{sbom_name}.{format}: {cve_id}: \
                             expected {expected_status_str}, got {}",
                            actual_status.as_str()
                        );
                    }
                    (Some(_), None) => {
                        panic!(
                            "{scenario_name}/{sbom_name}.{format}: {cve_id}: \
                             expected {expected_status_str}, but no verdict produced. \
                             Collected {} verdicts: {:?}",
                            collector.verdicts.len(),
                            collector
                                .verdicts
                                .iter()
                                .map(|v| format!(
                                    "{}={}",
                                    v.vulnerability_id,
                                    v.status.as_str()
                                ))
                                .collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
    }
}

// ---- Scenario tests ----

/// S5 relies on implied-affected logic (synthesizing `affected` for all versions below `fixed`)
/// which was removed because it is not spec-compliant. The upstream CSAF data does not use
/// `product_version_range` with VERS to declare affected ranges. See S5a for the spec-compliant
/// replacement.
#[test]
#[ignore = "TC-5643: upstream CSAF lacks VERS ranges; relied on removed implied-affected logic"]
fn scenario_s5_positive_baseline_openssl_cdx() {
    run_scenario_format("S5_positive_baseline_openssl_el8", "cdx");
}

#[test]
#[ignore = "TC-5641: CVE uses custom version scheme"]
fn scenario_s5_positive_baseline_openssl_spdx() {
    run_scenario_format("S5_positive_baseline_openssl_el8", "spdx");
}

#[test]
fn scenario_s6_positive_baseline_osv() {
    run_scenario("S6_positive_baseline_osv_urllib3");
}

#[test]
fn scenario_s7_cpeonly_node_hummingbird() {
    run_scenario("S7_cpeonly_node_hummingbird");
}

/// S8 relies on implied-affected logic (synthesizing `affected` for all versions below `fixed`)
/// which was removed because it is not spec-compliant. The upstream CSAF data does not use
/// `product_version_range` with VERS to declare affected ranges. See S8a for the spec-compliant
/// replacement.
#[test]
#[ignore = "TC-5643: upstream CSAF lacks VERS ranges; relied on removed implied-affected logic"]
fn scenario_s8_epoch_mismatch_openjdk_cdx() {
    run_scenario_format("S8_epoch_mismatch_openjdk", "cdx");
}

/// Same as S8 CDX — see doc comment above.
#[test]
#[ignore = "TC-5643: upstream CSAF lacks VERS ranges; relied on removed implied-affected logic"]
fn scenario_s8_epoch_mismatch_openjdk_spdx() {
    run_scenario_format("S8_epoch_mismatch_openjdk", "spdx");
}

/// The thunderbird sub-SBOMs expect `not_affected` from a versionless PURL
/// (`pkg:rpm/redhat/thunderbird`) declared `known_not_affected` in the CSAF advisory.
/// Per the PURL spec (ECMA-427), a versionless PURL is an identifier, not a wildcard
/// for all versions. Additionally, `sbom_combined_el8` expects `affected` for openssl
/// (CVE-2022-4304), which relied on the removed implied-affected logic — the upstream
/// CSAF lacks VERS ranges for affected versions.
#[test]
#[ignore = "TC-5643: upstream CSAF uses versionless PURLs and lacks VERS ranges"]
fn scenario_s10_combined_describing_cpe() {
    run_scenario("S10_combined_describing_cpe");
}

/// Same root cause as S10: the advisory declares `known_not_affected` for
/// `red_hat_enterprise_linux_8:thunderbird` which resolves to a versionless PURL.
/// A versionless PURL matcher only matches versionless components per spec.
#[test]
#[ignore = "TC-5643: upstream CSAF uses versionless PURLs for product-level not_affected"]
fn scenario_s12_notaffected_ignored_thunderbird() {
    run_scenario("S12_notaffected_ignored_thunderbird");
}

#[test]
fn scenario_s13_aliasless_osv_drop() {
    run_scenario("S13_aliasless_osv_drop");
}

#[test]
fn scenario_s1a_vers_crossstream_bind_libs() {
    run_scenario("S1a_vers_crossstream_bind-libs");
}

#[test]
fn scenario_s5a_vers_affected_openssl_el8() {
    run_scenario("S5a_vers_affected_openssl_el8");
}

#[test]
fn scenario_s8a_vers_epoch_openjdk() {
    run_scenario("S8a_vers_epoch_openjdk");
}

#[test]
fn scenario_s12a_vers_affected_thunderbird() {
    run_scenario("S12a_vers_affected_thunderbird");
}

// Known failing scenarios — ignored with issue references

#[test]
#[ignore = "TC-2621: cross-stream matching not yet resolved by version comparison alone"]
fn scenario_s1_crossstream_bind_libs() {
    run_scenario("S1_crossstream_bind-libs");
}

#[test]
#[ignore = "TC-2622: DATA — bare component name, no PURL/CPE; see S2a for data fix"]
fn scenario_s2_wrongscheme_golang_oci() {
    run_scenario("S2_wrongscheme_golang_oci");
}

#[test]
fn scenario_s2a_cpe_golang_oci() {
    run_scenario("S2a_cpe_golang_oci");
}

#[test]
#[ignore = "TC-2623: wrong product matching for hummingbird/curl"]
fn scenario_s3_wrongproduct_hummingbird_curl() {
    run_scenario("S3_wrongproduct_hummingbird_curl");
}

#[test]
#[ignore = "TC-2624: wrong product matching for satellite/chardet"]
fn scenario_s4_wrongproduct_satellite_chardet() {
    run_scenario("S4_wrongproduct_satellite_chardet");
}

#[test]
#[ignore = "TC-2625: substream filtering for openssl el8"]
fn scenario_s9_substream_openssl() {
    run_scenario("S9_substream_openssl_el8");
}

#[test]
#[ignore = "TC-2626: bare-affected substream filtering for firefox"]
fn scenario_s11_bareaffected_substream_firefox() {
    run_scenario("S11_bareaffected_substream_firefox");
}

#[test]
#[ignore = "TC-2628: cross-scheme PURL query for golang"]
fn scenario_s16_crossscheme_purlquery_golang() {
    run_scenario("S16_crossscheme_purlquery_golang");
}

#[test]
#[ignore = "TC-2629: cross-product OCP kernel/go matching"]
fn scenario_s17_crossproduct_ocp_kernel_go() {
    run_scenario("S17_crossproduct_ocp_kernel_go");
}

#[test]
#[ignore = "TC-2627: product status version filter for netty"]
fn scenario_s14_productstatus_versionfilter_netty() {
    run_scenario("S14_productstatus_versionfilter_netty");
}
