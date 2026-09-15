//! Scenario-based correlation tests and expected-verdict assertions.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use crate::{
    collector::VecCollector,
    engine::correlate,
    evidence::{Evidence, SbomEvidence},
    extract,
    memory::AdvisoryIndex,
    types::{ComponentId, SbomComponent, ScenarioExpected, Verdict, VerdictStatus, parse_purl},
};

const SCENARIO_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../etc/test-data/scenarios");
const CASES_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../etc/test-data/correlation/cases"
);
const SUITES_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../etc/test-data/correlation"
);

#[derive(Debug, serde::Deserialize)]
struct CorrelationCase {
    id: String,
    #[serde(default)]
    tags: Vec<String>,
    advisories: Vec<CaseAdvisory>,
    sboms: Vec<CaseSbom>,
    #[serde(default)]
    ignored: bool,
    #[serde(default)]
    ignore_reason: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CorrelationSuite {
    id: String,
    description: String,
    priority: u8,
    include_tags: Vec<String>,
    #[serde(default)]
    exclude_tags: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CaseAdvisory {
    path: String,
    vulnerability: String,
}

#[derive(Debug, serde::Deserialize)]
struct CaseSbom {
    id: String,
    #[serde(default)]
    artifacts: Vec<String>,
    #[serde(default)]
    components: Vec<CaseComponent>,
    expected: HashMap<String, VerdictStatus>,
}

#[derive(Debug, serde::Deserialize)]
struct CaseComponent {
    id: String,
    purl: Option<String>,
    checksum: Option<CaseChecksum>,
    cpe: Option<String>,
    expected: HashMap<String, VerdictStatus>,
}

#[derive(Debug, serde::Deserialize)]
struct CaseChecksum {
    algorithm: String,
    value: String,
}

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

    let mut advisories = AdvisoryIndex::new();

    for advisory_path in &expected.advisories {
        let full_path = dir.join(advisory_path);
        let json = load_json(&full_path);
        let evidence = extract::extract_advisory(advisory_path, &json).unwrap_or_else(|| {
            panic!("{scenario_name}: unrecognized advisory format: {advisory_path}")
        });
        advisories.add(evidence);
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
            let sbom = extract::extract_sbom(sbom_name, &sbom_json).unwrap_or_else(|| {
                panic!("{scenario_name}/{sbom_name}.{format}: failed to parse SBOM")
            });
            let evidence = Evidence::new(advisories.evidence(), sbom);
            let verdicts = correlate(&evidence, &mut collector);

            assert_expected_statuses(
                &format!("{scenario_name}/{sbom_name}.{format}"),
                &parse_legacy_expectations(&expectation.correct),
                &verdicts,
            );
        }
    }
}

fn load_case(case_dir: &Path) -> CorrelationCase {
    let manifest_path = case_dir.join("expected.json");
    let manifest_data = fs::read(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", manifest_path.display()));
    serde_json::from_slice(&manifest_data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", manifest_path.display()))
}

fn run_case(case_dir: &Path, case: &CorrelationCase) {
    let case_name = case_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("invalid case directory: {}", case_dir.display()));

    let mut advisories = AdvisoryIndex::new();
    for advisory in &case.advisories {
        let path = case_dir.join(&advisory.path);
        let json = load_json(&path);
        let evidence = extract::extract_advisory(&advisory.path, &json).unwrap_or_else(|| {
            panic!(
                "{}: unrecognized advisory format: {}",
                case.id, advisory.path
            )
        });
        assert!(
            evidence
                .assertions
                .iter()
                .any(|assertion| assertion.vulnerability_id == advisory.vulnerability),
            "{}: {} did not produce {}",
            case.id,
            advisory.path,
            advisory.vulnerability
        );
        advisories.add(evidence);
    }

    for sbom in &case.sboms {
        for artifact in &sbom.artifacts {
            let path = case_dir.join(artifact);
            let json = load_json(&path);
            let sbom_evidence = extract::extract_sbom(artifact, &json)
                .unwrap_or_else(|| panic!("{}/{}: failed to parse SBOM", case.id, artifact));
            let evidence = Evidence::new(advisories.evidence(), sbom_evidence);
            let mut collector = VecCollector::default();
            let verdicts = correlate(&evidence, &mut collector);

            assert_expected_statuses(
                &format!("{case_name}/{} ({artifact})", sbom.id),
                &sbom.expected,
                &verdicts,
            );
        }

        for component in &sbom.components {
            let component_id = component_id(component);
            let sbom_evidence = SbomEvidence {
                name: format!("{}/{}", case.id, component.id),
                components: vec![SbomComponent {
                    id: component_id,
                    context: Vec::new(),
                    grouping: Vec::new(),
                }],
                context: Vec::new(),
                grouping: Vec::new(),
            };
            let evidence = Evidence::new(advisories.evidence(), sbom_evidence);
            let mut collector = VecCollector::default();
            let verdicts = correlate(&evidence, &mut collector);

            assert_expected_statuses(
                &format!("{case_name}/{} ({})", sbom.id, component.id),
                &component.expected,
                &verdicts,
            );
        }
    }
}

fn component_id(component: &CaseComponent) -> ComponentId {
    let ids = [
        component.purl.is_some(),
        component.checksum.is_some(),
        component.cpe.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    assert_eq!(
        ids, 1,
        "component '{}' must define exactly one identity",
        component.id
    );

    if let Some(purl) = &component.purl {
        return parse_purl(purl)
            .unwrap_or_else(|| panic!("component '{}' has invalid PURL: {purl}", component.id));
    }
    if let Some(checksum) = &component.checksum {
        return ComponentId::Hash {
            algorithm: checksum.algorithm.clone(),
            value: checksum.value.clone(),
        };
    }
    ComponentId::Cpe(
        component
            .cpe
            .clone()
            .unwrap_or_else(|| panic!("component '{}' has no identity", component.id)),
    )
}

fn parse_legacy_expectations(expected: &HashMap<String, String>) -> HashMap<String, VerdictStatus> {
    expected
        .iter()
        .map(|(vulnerability_id, status)| (vulnerability_id.clone(), parse_expected_status(status)))
        .collect()
}

fn parse_expected_status(status: &str) -> VerdictStatus {
    match status {
        "affected" => VerdictStatus::Affected,
        "not_affected" => VerdictStatus::NotAffected,
        "fixed" => VerdictStatus::Fixed,
        "none" => VerdictStatus::None,
        other => panic!("unknown expected status: {other}"),
    }
}

fn assert_expected_statuses(
    label: &str,
    expected: &HashMap<String, VerdictStatus>,
    verdicts: &[Verdict],
) {
    // A definitive verdict from any component dominates a `none` result emitted for another
    // component in the same SBOM.
    let mut verdict_map: HashMap<String, VerdictStatus> = HashMap::new();
    for verdict in verdicts {
        let existing = verdict_map.get(&verdict.vulnerability_id);
        let keep_existing =
            existing.is_some_and(|status| verdict_rank(*status) >= verdict_rank(verdict.status));
        if !keep_existing {
            verdict_map.insert(verdict.vulnerability_id.clone(), verdict.status);
        }
    }

    for (vulnerability_id, expected_status) in expected {
        let actual = verdict_map.get(vulnerability_id.as_str());
        match actual {
            Some(actual_status) => {
                let ok = match *expected_status {
                    VerdictStatus::NotAffected => actual_status.resolves_affected(),
                    expected => *actual_status == expected,
                };
                assert!(
                    ok,
                    "{label}: {vulnerability_id}: expected {}, got {}",
                    expected_status.as_str(),
                    actual_status.as_str()
                );
            }
            None => {
                panic!(
                    "{label}: {vulnerability_id}: expected {}, but no verdict produced. \
                     Collected {} verdicts: {:?}",
                    expected_status.as_str(),
                    verdicts.len(),
                    verdicts
                        .iter()
                        .map(|v| format!("{}={}", v.vulnerability_id, v.status.as_str()))
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}

fn verdict_rank(status: VerdictStatus) -> u8 {
    match status {
        VerdictStatus::None => 0,
        VerdictStatus::UnderInvestigation => 1,
        VerdictStatus::Affected => 2,
        VerdictStatus::NotAffected => 3,
        VerdictStatus::Fixed => 4,
    }
}

#[test]
fn correlation_cases() {
    run_suite("priority0", false);
}

#[test]
fn correlation_priority1_cases() {
    run_suite("priority1", false);
}

#[test]
#[ignore = "runs intentionally pending correlation cases"]
fn ignored_correlation_cases() {
    run_suite("priority0", true);
}

fn run_suite(suite_id: &str, ignored_only: bool) {
    let suite_path = PathBuf::from(SUITES_DIR).join(format!("{suite_id}.json"));
    let suite_data = fs::read(&suite_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", suite_path.display()));
    let suite: CorrelationSuite = serde_json::from_slice(&suite_data)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", suite_path.display()));

    let cases = case_dirs()
        .into_iter()
        .map(|path| {
            let case = load_case(&path);
            (case.id.clone(), (path, case))
        })
        .collect::<HashMap<_, _>>();
    let selected_case_ids = selected_case_ids(&suite, &cases);
    assert!(
        !selected_case_ids.is_empty(),
        "suite {} selected no cases",
        suite.id
    );

    println!(
        "suite '{}' [priority {}] - {}",
        suite.id, suite.priority, suite.description
    );

    let mut active_cases = 0;
    let mut pending_cases = 0;
    for case_id in selected_case_ids {
        let (case_dir, case) = cases
            .get(&case_id)
            .unwrap_or_else(|| panic!("suite {suite_id} references unknown case {case_id}"));
        let tags = if case.tags.is_empty() {
            "untagged".to_string()
        } else {
            case.tags.join(", ")
        };

        if case.ignored {
            pending_cases += 1;
        }
        if case.ignored != ignored_only {
            if case.ignored {
                println!(
                    "  IGNORE {} [{}] - {}",
                    case.id,
                    tags,
                    case.ignore_reason.as_deref().unwrap_or("pending")
                );
            }
            continue;
        }

        if !ignored_only {
            active_cases += 1;
        }
        run_case(case_dir, case);
        println!(
            "  {} {} [{}]",
            if ignored_only { "PENDING" } else { "PASS" },
            case.id,
            tags
        );
    }

    if !ignored_only {
        println!("  cases: {active_cases} passed, {pending_cases} pending");
        assert!(active_cases > 0, "suite {suite_id} has no active cases");
    } else {
        println!("  pending cases exercised: {pending_cases}");
    }
}

fn selected_case_ids(
    suite: &CorrelationSuite,
    cases: &HashMap<String, (PathBuf, CorrelationCase)>,
) -> Vec<String> {
    let mut selected = cases
        .iter()
        .filter(|(_, (_, case))| {
            suite
                .include_tags
                .iter()
                .all(|tag| case.tags.iter().any(|case_tag| case_tag == tag))
                && suite
                    .exclude_tags
                    .iter()
                    .all(|tag| !case.tags.iter().any(|case_tag| case_tag == tag))
        })
        .map(|(case_id, _)| case_id.clone())
        .collect::<Vec<_>>();
    selected.sort();
    selected
}

fn case_dirs() -> Vec<PathBuf> {
    let mut case_dirs = fs::read_dir(CASES_DIR)
        .unwrap_or_else(|e| panic!("failed to read {CASES_DIR}: {e}"))
        .map(|entry| entry.unwrap_or_else(|e| panic!("failed to read correlation case: {e}")))
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    case_dirs.sort();
    case_dirs
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
fn scenario_s3a_vers_wrongproduct_hummingbird_curl() {
    run_scenario("S3a_vers_wrongproduct_hummingbird_curl");
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
