# Correlation scenarios

The correlation service harness reads `expected*.json` manifests containing advisory paths and
SBOM filename → component node ID → vulnerability → verdict maps. It runs extraction after each
ingestion, in both document orders, then checks the complete verdict map and summary counts.
Empty maps mean no applicable evidence. Explicit `not_affected` and `fixed` remain distinct.
Publisher conventions such as Red Hat `fixed_is_first_fixed` and `versionless_purl` must be named
in a scenario's review; they are not general CSAF rules.

## Migration review of the remaining original scenarios

| Scenario | Disposition | Main correction or remaining question |
|---|---|---|
| [S4](S4_wrongproduct_satellite_chardet/README.md) | Migrated | Unrelated Satellite statements yield no verdict, not an explicit negative |
| [S5](S5_positive_baseline_openssl_el8/README.md) | Migrated | At-fix is fixed; upstream CVE and CSAF tested separately |
| [S7](S7_cpeonly_node_hummingbird/README.md) | Interpretation unresolved | Product CPE plus package name needs an explicit publisher policy |
| [S8](S8_epoch_mismatch_openjdk/README.md) | Migrated concrete cases | Below-fix examples do not prove general epoch invariance |
| [S9](S9_substream_openssl_el8/README.md) | Migrated | At-fix is fixed; own-stream rule is explicit |
| [S10](S10_combined_describing_cpe/README.md) | Migrated | Assert each component; isolate CVE, CSAF, and OSV inputs |
| [S11](S11_bareaffected_substream_firefox/README.md) | Blocked | Flatpak `rpmmod` negative incorrectly applies to base Firefox |
| [S12](S12_notaffected_ignored_thunderbird/README.md) | Original migrated; control blocked | Removing negative exposes an affected result from inapplicable statements |
| [S15](S15_versioncmp_rpm_openssh/README.md) | Migrated | Mainline minor fallback is allowed; patched builds are fixed |
| [S17](S17_crossproduct_ocp_kernel_go/README.md) | Migrated | Unrelated kernel has no verdict; patched Go builds are fixed |
| [S30](S30_crossproduct_curl_notaffected/README.md) | Migrated | RHEL 8 explicit negative; RHEL 9 patched builds fixed |

Nine additional scenarios are enabled. Together with the previous 15, the harness covers 24
scenarios through 35 manifests (70 ingestion-order tests), with both SBOM formats for all newly
migrated original cases. Dedicated digest-S18 and SKU-S19 extractor tests remain separate.

The original advisory documents are unchanged. Historical legacy-engine result tables have been
replaced by reviews. S7 and S11 retain their legacy `expected.json` files as historical artifacts,
not accepted new-engine expectations. Reviewed blocked manifests are kept for future fixes:

- S11 `expected-reviewed.json`: mainline Firefox affected, EUS exact-fix Firefox fixed.
- S12 `expected-control.json`: no verdict after removing all negative assertions from the synthetic control.

Migration trials reproduce the S11 and S12 discrepancies in both ingestion orders. These manifests
are deliberately not registered as acceptance cases; no ignored or output-derived tests are added.
To reproduce after a fix, register each manifest as another case of `service::test::scenario`.
Keep the S12 original and control in separate cases/databases because their document IDs match.

## Validation

```sh
cargo test -p trustify-module-correlation --locked -- --test-threads=4
cargo fmt --all -- --check
```

A passing verdict does not alone prove every contributing evidence row is correctly scoped;
the S12 control demonstrates that limitation. Existing focused PURL extractor tests retain
assertions on chosen streams, ranges, statuses, and contexts. Product-scoping and qualifier fixes
must add evidence-level regressions before enabling the blocked manifests.
