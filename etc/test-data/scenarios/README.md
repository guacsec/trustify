# Correlation scenarios

The correlation service harness reads `expected*.json` manifests containing advisory paths and
SBOM filename → component node ID → vulnerability → verdict maps. It runs extraction after each
ingestion, in both document orders, then checks the complete verdict map and summary counts.
Empty maps mean no applicable evidence. Explicit `not_affected` and `fixed` remain distinct.
Publisher conventions such as Red Hat `fixed_is_first_fixed` and `versionless_purl` must be named
in a scenario's review; they are not general CSAF rules.

## Scenario status

This table records the review of `92ac7ba20` against local `main` at `eddf6345c` on
2026-10-19. The correlation module test run passed 246 tests with no failures or ignored tests,
including 78 common-harness tests. “Passing” refers to that run, not a fresh validation of every
subsequent commit. S8's documentation was clarified on 2026-10-20: missing RPM epoch means zero;
its remaining follow-up is additional regression coverage.

These results describe the new correlation engine. Most legacy fundamental-API scenario tests
remain ignored; `main` was compared through source and expectations, not executed separately.

| Scenario | State | Remaining gap or notable change |
|---|---|---|
| [S1 — bind-libs streams](S1_crossstream_bind-libs/README.md) | Passing | Distinguishes fixed, explicit negative, and no verdict |
| [S2 — golang product/scheme](S2_wrongscheme_golang_oci/README.md) | Passing | Official PURL-bearing VEX replaces synthetic bare-name input |
| [S3 — curl wrong product](S3_wrongproduct_hummingbird_curl/README.md) | Passing | Product isolation and explicit statuses |
| [S4 — Satellite/chardet](S4_wrongproduct_satellite_chardet/README.md) | Passing | Unrelated statements produce no verdict |
| [S5 — OpenSSL baseline](S5_positive_baseline_openssl_el8/README.md) | Passing | At-fix correctly yields fixed |
| [S6 — urllib3 OSV](S6_positive_baseline_osv_urllib3/README.md) | Passing | Multiple affected intervals; outside ranges yields no verdict |
| [S7 — Hummingbird package/CPE](S7_cpeonly_node_hummingbird/README.md) | Unresolved | Package identity versus product-context interpretation |
| [S8 — OpenJDK epoch](S8_epoch_mismatch_openjdk/README.md) | Passing | Missing epoch means zero; additional boundary tests would strengthen coverage |
| [S9 — OpenSSL substream](S9_substream_openssl_el8/README.md) | Passing | Own-stream fix selection |
| [S10 — combined SBOM](S10_combined_describing_cpe/README.md) | Passing | Component-level expectations and isolated advisory formats |
| [S11 — Firefox](S11_bareaffected_substream_firefox/README.md) | Passing | Module qualifiers prevent Flatpak negatives leaking to base packages |
| [S12 — Thunderbird](S12_notaffected_ignored_thunderbird/README.md) | Passing | Negative-removal control also confirms no unrelated evidence |
| [S13 — aliasless OSV](S13_aliasless_osv_drop/README.md) | Passing | Native GHSA ID preserved |
| [S14 — Netty](S14_productstatus_versionfilter_netty/README.md) | Passing | Official VEX changes positive component to `netty-codec` |
| [S15 — OpenSSH](S15_versioncmp_rpm_openssh/README.md) | Passing | Mainline-minor fallback changes below-fix `el8_10` to affected |
| [S16 — cross-scheme query](S16_crossscheme_purlquery_golang/README.md) | Passing | Official PURL-bearing VEX; no OCI/Maven leakage |
| [S17 — OCP/kernel/Go](S17_crossproduct_ocp_kernel_go/README.md) | Passing | Unrelated kernel excluded; patched Go fixed |
| [S18 — digests](S18_digest_correlation/README.md) | Focused tests passing | No common verdict manifest; architecture/range limitations noted in review |
| [S19 — hardware identifiers](S19_sku_correlation/README.md) | Focused tests passing | No common verdict manifest; wildcard advisory is synthetic |
| [S20 — WAGO CPE ranges](S20_cpe_range_wago/README.md) | Passing | CycloneDX only |
| [S21 — CPE extended attributes](S21_cpe_extended_attributes_beckhoff/README.md) | Passing fixtures | Missing CPE boundary-status handling; CycloneDX only |
| [S22 — third-party OpenSSL CPE](S22_cpe_third_party_openssl_phoenix/README.md) | Passing fixtures | Generic-version range limitation; CycloneDX only |
| [S23 — SUSE codestreams](S23_suse_codestream_openssl/README.md) | Passing with conflict | Broad GA/SP6 context overlap remains |
| [S24 — RHEL 10 minors](S24_rhel10_minor_streams_ubi10/README.md) | Passing | CycloneDX only |
| [S25 — CVE packageURL](S25_cve_package_url/README.md) | Passing | CycloneDX only |
| [S26 — CVE cpeApplicability](S26_cve_cpe_applicability_kernel/README.md) | Passing | CycloneDX only |
| [S27 — identifier synonyms](S27_cve_identifier_synonyms_log4j/README.md) | Passing | CycloneDX only; relevant to resolving S7 |
| [S28 — fixed then regression](S28_fixed_then_regression/README.md) | Passing | Explicit regression overrides inferred fix |
| [S29 — provider precedence](S29_provider_weighting/README.md) | Passing | Provider aliases and temporary context covered |
| [S30 — curl cross-product](S30_crossproduct_curl_notaffected/README.md) | Passing | Renamed from `main`'s original S18 |

## Current coverage

The [service harness](../../../modules/correlation/src/service/test.rs) covers 27 scenarios through
39 manifests (78 ingestion-order tests). S7 is the only numbered scenario without accepted
new-engine coverage. S18 (digests) and S19 (hardware identifiers) have separate extractor and
service tests, but no full-verdict manifests in the common harness.

All migrated original scenarios cover both CycloneDX and SPDX. S20–S22 and S24–S27 currently
cover CycloneDX only. S23, S28, and S29 cover both formats. The original S18 curl cross-product
scenario is now S30; S18 now identifies the digest scenario.

Historical legacy-engine result tables have been replaced by reviews. S7 and S11 retain their
legacy `expected.json` files as historical artifacts, not accepted new-engine expectations.
The harness registers these reviewed manifests in both ingestion orders and both SBOM formats:

- S11 `expected-reviewed.json`: mainline Firefox affected, EUS exact-fix Firefox fixed.
- S12 `expected-control.json`: no verdict after removing all negative assertions from the synthetic control.

S11 also has evidence-level controls for base, matching-module, and different-module packages,
including identifier queries and both extraction directions. S12 has an additional extractor
test requiring the control to produce no PURL evidence.
Keep the S12 original and control in separate cases/databases because their document IDs match.

## Changes from the original scenarios

Legacy expectations used `not_affected` for "not reported", including fixed builds and unrelated
statements. The new manifests distinguish `fixed`, explicit `not_affected`, and no verdict, and
identify the component receiving each verdict.

S2, S14, and S16 use official PURL-bearing VEX documents in place of the synthetic bare-name
advisories used by the legacy tests. S14's positive component consequently changes from
`netty-codec-http` to `netty-codec`. These cases do not establish support for the original bare-name
matching path. S15 also changes the below-fix `el8_10` expectation to `affected` under the configured
mainline-minor fallback policy.

Most scenario tests of the deprecated fundamental APIs remain ignored. Passing the new service
harness does not establish that those legacy endpoints satisfy the migrated expectations.

## Remaining gaps

- S7 needs an accepted interpretation of package-associated product CPEs, consistent with S27's
  identifier-synonym handling.
- S8 has a regression-coverage follow-up: add at/above-fix controls with omitted, explicit zero,
  and nonzero epochs. RPM already defines missing epoch as zero; there is no unresolved policy.
- S18 still exposes architecture-insensitive PURL matching and unsupported Debian/BSD range comparison.
- S21 lacks CPE `first_*`/`last_*` status handling; S22 retains a generic-version range limitation.
- S23 accepts an affected verdict with a conflict for `openssl` / CVE-2025-9230 because broad GA and
  SP6 product contexts both match. More precise applicability remains a separate concern.
- S18/S19 need common full-verdict manifests, and the CycloneDX-only cases lack SPDX counterparts.
- No registered scenario manifest expects `under_investigation`. The harness invokes extraction
  directly, so it does not verify worker scheduling, retries, or update/deprecation lifecycle behavior.

## Validation

```sh
cargo test -p trustify-module-correlation --locked -- --test-threads=4
cargo fmt --all -- --check
```

A passing verdict does not alone prove every contributing evidence row is correctly scoped;
the S12 control guards against that limitation. Existing focused PURL extractor tests retain
assertions on chosen streams, ranges, statuses, and contexts. Product-scoping and qualifier fixes
should retain evidence-level regressions alongside the verdict checks.
