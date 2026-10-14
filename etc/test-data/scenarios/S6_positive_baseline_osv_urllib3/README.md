# S6 — Positive baseline: OSV / language-ecosystem path (urllib3)

Isolates the **OSV / language-ecosystem** path: exact purl (name + ecosystem) + explicit version range
(standard §6). Regression guard that a version-in-range dep reports, a patched one doesn't, and a
different ecosystem doesn't collide.

## Data
`osv/GHSA-g4mx-q9vg-27p4.json` (aliases `CVE-2023-45803`, `PYSEC-2023-212`), affects `pkg:pypi/urllib3`
in two `affected` entries: ranges `[2.0.0, 2.0.7)` and `[0, 1.26.18)`.

OSV only defines the set of affected versions. A `fixed` event ends an interval, it isn't a status
of the fixed version, so a version outside of the affected set gets no verdict (as on OSV.dev and in
Dependency-Track).

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed) | CVE-2023-45803 |
|---|---|
| `sbom_urllib3_affected` (`pypi/urllib3@1.26.17`) | affected |
| `sbom_urllib3_v203` (`pypi/urllib3@2.0.3`) | affected |
| `sbom_urllib3_patched` (`pypi/urllib3@1.26.18`) | — |
| `sbom_urllib3_abovefix` (`pypi/urllib3@1.26.20`) | — |
| `sbom_python3-urllib3_rpm_el8` (`rpm/redhat/python3-urllib3@1.24.2-5.el8`) | — |

- **affected** — `1.26.17 ∈ [0, 1.26.18)` → affected.
- **v203** — `2.0.3 ∈ [2.0.0, 2.0.7)` → affected, although above the fix of the other entry.
- **patched**, **abovefix** — outside of the affected set → no verdict.
- **rpm** — different ecosystem (rpm vs PyPI) and name → the PyPI record doesn't apply (§6) → no
  verdict.

## Files
- SBOMs: `sbom_urllib3_{affected,v203,patched,abovefix}.{cdx,spdx}.json`,
  `sbom_python3-urllib3_rpm_el8.{cdx,spdx}.json`.
- Advisory: `osv/GHSA-g4mx-q9vg-27p4.json` (only the OSV record is ingested; `cve/` MITRE copy is not).
