# Correlation scenarios

The correlation service harness reads `expected*.json` manifests containing advisory paths and
SBOM filename → component node ID → vulnerability → verdict maps. It runs extraction after each
ingestion, in both document orders, then checks the complete verdict map and summary counts.
Empty maps mean no applicable evidence. Explicit `not_affected` and `fixed` remain distinct.
Publisher conventions such as Red Hat `fixed_is_first_fixed` and `versionless_purl` must be named
in a scenario's review; they are not general CSAF rules.

## Migration review

| Scenario | Disposition | Main correction or remaining question |
|---|---|---|
| [S4](S4_wrongproduct_satellite_chardet/README.md) | Migrated | Unrelated Satellite statements yield no verdict, not an explicit negative |
| [S5](S5_positive_baseline_openssl_el8/README.md) | Migrated | At-fix is fixed; upstream CVE and CSAF tested separately |
| [S7](S7_cpeonly_node_hummingbird/README.md) | Interpretation unresolved | Product CPE plus package name needs an explicit publisher policy |
| [S8](S8_epoch_mismatch_openjdk/README.md) | Migrated | Missing RPM epoch means zero; additional boundary controls would strengthen regression coverage |
| [S9](S9_substream_openssl_el8/README.md) | Migrated | At-fix is fixed; own-stream rule is explicit |
| [S10](S10_combined_describing_cpe/README.md) | Migrated | Assert each component; isolate CVE, CSAF, and OSV inputs |
| [S11](S11_bareaffected_substream_firefox/README.md) | Migrated | Module qualifiers prevent the Flatpak negative from applying to base Firefox |
| [S12](S12_notaffected_ignored_thunderbird/README.md) | Original and control migrated | Removing the negative leaves no evidence; extended-support fixes do not apply to the mainline package |
| [S15](S15_versioncmp_rpm_openssh/README.md) | Migrated | Mainline minor fallback is allowed; patched builds are fixed |
| [S17](S17_crossproduct_ocp_kernel_go/README.md) | Migrated | Unrelated kernel has no verdict; patched Go builds are fixed |
| [S30](S30_crossproduct_curl_notaffected/README.md) | Migrated | RHEL 8 explicit negative; RHEL 9 patched builds fixed |

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
