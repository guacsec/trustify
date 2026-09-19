# S4 — Wrong product, clean whole-CVE-false (python3-chardet)

Isolates **product scoping** in its cleanest form: `python3-chardet` appears in these CVEs **only** under
**Red Hat Satellite** (`cpe:/a:redhat:satellite:*`, built `el7ar`). RHEL 8 has **no** chardet statement at
all, so an el8 box is not affected — the whole CVE is absent for it (standard §5/§7).

## Data — `python3-chardet` statements
| CVE | RHEL 8 | Satellite |
|---|---|---|
| CVE-2018-11751 | (absent) | `fixed` under `satellite:6.8::el7` |
| CVE-2018-3258 | (absent) | `fixed` under `satellite:6.8::el7` |
| CVE-2019-0231 | (absent) | `fixed` under `satellite:6.7::el7` |

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `python3-chardet`) | CVE-2018-11751 | CVE-2018-3258 | CVE-2019-0231 |
|---|---|---|---|
| `sbom_python3-chardet_el8` (`3.0.4-7.el8`) | not_affected | not_affected | not_affected |
| `sbom_python3-chardet_el8_el8cpe` (`3.0.4-7.el8`) | not_affected | not_affected | not_affected |

Satellite ≠ RHEL 8 (different product **and** version line, `el7ar`), and el8 has no chardet entry → every
cell is not_affected. The two SBOMs differ only in CPE placement → same verdict.

## Files
- SBOMs: `sbom_python3-chardet_el8.{cdx,spdx}.json`, `sbom_python3-chardet_el8_el8cpe.{cdx,spdx}.json`.
- Advisories: `vex/CVE-2018-11751.json`, `vex/CVE-2018-3258.json`, `vex/CVE-2019-0231.json` (Red Hat CSAF); `cve/` MITRE records.
