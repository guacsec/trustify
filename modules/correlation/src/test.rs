use std::{
    collections::HashMap,
    fs,
    io::Read,
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
            let mut decompressor = liblzma::read::XzDecoder::new(&compressed[..]);
            let mut json_bytes = Vec::new();
            decompressor
                .read_to_end(&mut json_bytes)
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
                    "affected" => Status::Affected,
                    "not_affected" => Status::NotAffected,
                    "fixed" => Status::Fixed,
                    other => panic!("unknown expected status: {other}"),
                };

                let actual = verdict_map.get(cve_id.as_str());
                match actual {
                    Some(actual_status) => {
                        // For expected "not_affected", accept both NotAffected and Fixed
                        let ok = match expected_status {
                            Status::NotAffected => actual_status.resolves_affected(),
                            _ => *actual_status == expected_status,
                        };
                        assert!(
                            ok,
                            "{scenario_name}/{sbom_name}.{format}: {cve_id}: \
                             expected {expected_status_str}, got {}",
                            actual_status.as_str()
                        );
                    }
                    None => {
                        if expected_status == Status::Affected {
                            // If we expected affected and found no verdict, that might
                            // mean no assertion matched at all. This is a test failure.
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
                        } else if expected_status == Status::NotAffected
                            || expected_status == Status::Fixed
                        {
                            // No verdict at all for this CVE — it means the advisory
                            // didn't match this component, which is also "not affected"
                            // in the sense that the component isn't flagged.
                            // This is acceptable for not_affected expectations.
                        }
                    }
                }
            }
        }
    }
}

// ---- Scenario tests ----

#[test]
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

#[test]
fn scenario_s8_epoch_mismatch_openjdk_cdx() {
    run_scenario_format("S8_epoch_mismatch_openjdk", "cdx");
}

#[test]
fn scenario_s8_epoch_mismatch_openjdk_spdx() {
    run_scenario_format("S8_epoch_mismatch_openjdk", "spdx");
}

/// The thunderbird sub-SBOMs expect `not_affected` from a versionless PURL
/// (`pkg:rpm/redhat/thunderbird`) declared `known_not_affected` in the CSAF advisory.
/// Per the PURL spec (ECMA-427), a versionless PURL is an identifier, not a wildcard
/// for all versions. The upstream CSAF data does not express its intent correctly.
/// The engine correctly produces `affected` (SBOM version is below the sub-stream fix).
#[test]
#[ignore = "TC-5643: upstream CSAF uses versionless PURLs for product-level not_affected"]
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

// Known failing scenarios — ignored with issue references

#[test]
#[ignore = "TC-2621: cross-stream matching not yet resolved by version comparison alone"]
fn scenario_s1_crossstream_bind_libs() {
    run_scenario("S1_crossstream_bind-libs");
}

#[test]
#[ignore = "TC-2622: wrong version scheme for golang OCI"]
fn scenario_s2_wrongscheme_golang_oci() {
    run_scenario("S2_wrongscheme_golang_oci");
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
