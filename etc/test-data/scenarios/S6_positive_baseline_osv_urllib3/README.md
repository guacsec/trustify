# S6 — Positive baseline: OSV / language-ecosystem path (urllib3)

Isolates the **OSV / language-ecosystem** path: exact purl (name + ecosystem) + explicit version range
(standard §6). Regression guard that a version-in-range dep reports, a patched one doesn't, and a
different ecosystem doesn't collide.

## Data
`osv/GHSA-g4mx-q9vg-27p4.json` (aliases `CVE-2023-45803`, `PYSEC-2023-212`), affects `pkg:pypi/urllib3`
ranges `[2.0.0, 2.0.7)` and `[0, 1.26.18)`.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed) | CVE-2023-45803 |
|---|---|
| `sbom_urllib3_affected` (`pypi/urllib3@1.26.17`) | affected |
| `sbom_urllib3_patched` (`pypi/urllib3@1.26.18`) | not_affected |
| `sbom_python3-urllib3_rpm_el8` (`rpm/redhat/python3-urllib3@1.24.2-5.el8`) | not_affected |

- **affected** — `1.26.17 ∈ [0, 1.26.18)` → affected.
- **patched** — `1.26.18` is the exclusive `fixed` bound → not_affected.
- **rpm** — different ecosystem (rpm vs PyPI) and name → the PyPI record doesn't apply (§6) → not_affected.

## Files
- SBOMs: `sbom_urllib3_affected.{cdx,spdx}.json`, `sbom_urllib3_patched.{cdx,spdx}.json`, `sbom_python3-urllib3_rpm_el8.{cdx,spdx}.json`.
- Advisory: `osv/GHSA-g4mx-q9vg-27p4.json` (only the OSV record is ingested; `cve/` MITRE copy is not).
