# S10 — Combined el8 box: product + language deps, correctly scoped

A full-fidelity el8 box mixing both paths: RPMs (`product_status`) and a language dep (`purl_status`),
plus a thunderbird pair where the correct verdict is driven by `known_not_affected` + product scoping
(standard §5/§7). CPE placement (root vs child) does not change ground truth.

## `sbom_combined_el8` (describing CPE `enterprise_linux:8`)
| Component | CVE | standard | verdict |
|---|---|---|---|
| openssl `1:1.1.1k-7.el8` | CVE-2022-4304 | below el8 fix `1.1.1k-9.el8_7` (§3) | affected |
| urllib3 `1.26.17` (pypi) | CVE-2023-45803 | in OSV range `[0,1.26.18)` (§6) | affected |
| bind-libs `9.11.36-16.el8_10.8` | CVE-2024-4076 | el8 `known_not_affected`; el9 fix is another stream (§5) | not_affected |

## thunderbird pair (`115.10.1-1.el8`, CVE-2024-6602)
el8 GA thunderbird is `known_not_affected`; every `fixed` row is a **sub-stream** product
(`rhel_eus/aus/e4s/tus:8.x`, distinct products §5) → **not_affected**. Both SBOMs are the same el8 GA box;
they differ only in where the CPE sits, so the correct verdict is identical.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM | CVE-2022-4304 | CVE-2023-45803 | CVE-2024-4076 | CVE-2024-6602 |
|---|---|---|---|---|
| `sbom_combined_el8` | affected | affected | not_affected | — |
| `sbom_thunderbird_el8_root-cpe` | — | — | — | not_affected |
| `sbom_thunderbird_el8_child-cpe` | — | — | — | not_affected |

## Files
- SBOMs: `sbom_combined_el8.{cdx,spdx}.json`, `sbom_thunderbird_el8_root-cpe.{cdx,spdx}.json`, `sbom_thunderbird_el8_child-cpe.{cdx,spdx}.json`.
- Advisories: `vex/CVE-2022-4304.json`, `vex/CVE-2024-4076.json`, `vex/CVE-2024-6602.json` (Red Hat CSAF); `osv/GHSA-g4mx-q9vg-27p4.json` (urllib3); `cve/` MITRE records.
