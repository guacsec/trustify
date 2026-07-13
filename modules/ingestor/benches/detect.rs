#![allow(clippy::expect_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use trustify_module_ingestor::service::{DocumentDetector, Format};
use trustify_test_context::document_bytes;

fn load_fixture(path: &str) -> Vec<u8> {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async { document_bytes(path).await.expect("fixture").to_vec() })
}

/// Try direct parse to each domain type in order, falling through on failure.
/// Returns the Format if any parse succeeds, None if all fail.
#[allow(clippy::unwrap_used)]
fn try_parse_direct(bytes: &[u8]) -> Option<Format> {
    if serde_json::from_slice::<csaf::Csaf>(bytes).is_ok() {
        return Some(Format::CSAF);
    }
    if serde_json::from_slice::<cve::Cve>(bytes).is_ok() {
        return Some(Format::CVE);
    }
    if serde_json::from_slice::<osv::schema::Vulnerability>(bytes).is_ok() {
        return Some(Format::OSV);
    }
    if serde_json::from_slice::<serde_cyclonedx::cyclonedx::v_1_6::CycloneDx>(bytes).is_ok() {
        return Some(Format::CycloneDX);
    }
    if serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("spdxVersion").cloned())
        .is_some()
    {
        return Some(Format::SPDX);
    }
    None
}

fn bench_detect(c: &mut Criterion) {
    let csaf = load_fixture("csaf/CVE-2023-20862.json");
    let osv_json = load_fixture("osv/RUSTSEC-2021-0079.json");
    let osv_yaml = load_fixture("osv/RSEC-2023-6.yaml");
    let cve = load_fixture("mitre/CVE-2024-27088.json");
    let spdx = load_fixture("ubi9-9.2-755.1697625012.json");
    let cyclonedx = load_fixture("zookeeper-3.9.2-cyclonedx.json");

    let mut group = c.benchmark_group("detect");

    // Current DocumentDetector approach (Value intermediate)
    group.bench_function("csaf_unknown", |b| {
        b.iter(|| DocumentDetector::detect(black_box(&csaf)))
    });
    group.bench_function("csaf_advisory", |b| {
        b.iter(|| DocumentDetector::detect_as(black_box(&csaf), Format::Advisory))
    });
    group.bench_function("csaf_concrete", |b| {
        b.iter(|| DocumentDetector::detect_as(black_box(&csaf), Format::CSAF))
    });

    group.bench_function("osv_json_unknown", |b| {
        b.iter(|| DocumentDetector::detect(black_box(&osv_json)))
    });
    group.bench_function("osv_yaml_unknown", |b| {
        b.iter(|| DocumentDetector::detect(black_box(&osv_yaml)))
    });

    group.bench_function("cve_unknown", |b| {
        b.iter(|| DocumentDetector::detect(black_box(&cve)))
    });

    group.bench_function("spdx_unknown", |b| {
        b.iter(|| DocumentDetector::detect(black_box(&spdx)))
    });
    group.bench_function("spdx_sbom", |b| {
        b.iter(|| DocumentDetector::detect_as(black_box(&spdx), Format::SBOM))
    });
    group.bench_function("spdx_concrete", |b| {
        b.iter(|| DocumentDetector::detect_as(black_box(&spdx), Format::SPDX))
    });

    group.bench_function("cyclonedx_unknown", |b| {
        b.iter(|| DocumentDetector::detect(black_box(&cyclonedx)))
    });
    group.bench_function("cyclonedx_concrete", |b| {
        b.iter(|| DocumentDetector::detect_as(black_box(&cyclonedx), Format::CycloneDX))
    });

    // Try-parse approach: attempt direct serde_json::from_slice to each domain type
    group.bench_function("tryparse_csaf", |b| {
        b.iter(|| try_parse_direct(black_box(&csaf)))
    });
    group.bench_function("tryparse_osv_json", |b| {
        b.iter(|| try_parse_direct(black_box(&osv_json)))
    });
    group.bench_function("tryparse_cve", |b| {
        b.iter(|| try_parse_direct(black_box(&cve)))
    });
    group.bench_function("tryparse_spdx", |b| {
        b.iter(|| try_parse_direct(black_box(&spdx)))
    });
    group.bench_function("tryparse_cyclonedx", |b| {
        b.iter(|| try_parse_direct(black_box(&cyclonedx)))
    });

    group.finish();
}

criterion_group!(benches, bench_detect);
criterion_main!(benches);
