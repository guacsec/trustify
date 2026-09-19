# S1 — Cross-stream: judge the box against its own stream (bind-libs)

Isolates **stream scoping**. `bind-libs` has a different version line per RHEL release (el8 = 9.11,
el9 = 9.16, el10 = 9.18). A box must be judged against its own stream's statement/fix line, never
another stream's fix (standard §1.2, §5, §3 z-stream lines).

## Data — advisory `bind-libs` statements
| CVE | el8 | RHEL 9 (GA) fix | 9.0 z-stream fix | el10 |
|---|---|---|---|---|
| CVE-2022-0396 | known_not_affected | `9.16.23-5.el9_1` | — (none) | (no entry) |
| CVE-2023-5517 | known_not_affected | `9.16.23-18.el9_4.1` | `rhel_eus:9.0` `9.16.23-1.el9_0.5` | known_affected |
| CVE-2024-4076 | known_not_affected | `9.16.23-18.el9_4.6` | `rhel_e4s:9.0` `9.16.23-1.el9_0.7` | known_affected |

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `bind-libs`) | CVE-2022-0396 | CVE-2023-5517 | CVE-2024-4076 |
|---|---|---|---|
| `sbom_bind-libs_el8.10` (`9.11.36-16.el8_10.8`) | not_affected | not_affected | not_affected |
| `sbom_bind-libs_el8.10_describing-cpe` (same build) | not_affected | not_affected | not_affected |
| `sbom_bind-libs_el9.0_below-fix` (`9.16.23-1.el9_0.6`) | affected | not_affected | affected |
| `sbom_bind-libs_el9.0_at-fix` (`9.16.23-1.el9_0.7`) | affected | not_affected | not_affected |
| `sbom_bind-libs_el9.0_above-fix` (`9.16.23-1.el9_0.8`) | affected | not_affected | not_affected |
| `sbom_bind-libs_el10` (`9.18.37-1.el10`) | not_affected | affected | affected |

- **el8** — `known_not_affected`, no el8 `bind-libs` fix → not_affected (el8's affected package is the
  differently-named `bind9.16-libs`). Both el8 SBOMs are the same box (only CPE placement differs) → same verdict.
- **el9.0** — judged against the 9.0 z-stream fix when present: CVE-2024-4076 (`e4s:9.0` `-1.el9_0.7`)
  `.6` below → affected, `.7` at → not, `.8` above → not; CVE-2023-5517 (`eus:9.0` `-1.el9_0.5`) all ≥ → not.
  CVE-2022-0396 has no 9.0 fix, only the RHEL 9 `-5.el9_1` → all `el9_0.*` below → affected.
- **el10** — CVE-2022-0396 has no el10 statement → not_affected; CVE-2023-5517 / CVE-2024-4076 are el10
  `known_affected` (version-less) → affected.

## Files
- SBOMs: `sbom_bind-libs_*.{cdx,spdx}.json` (6).
- Advisories: `vex/CVE-2022-0396.json`, `vex/CVE-2023-5517.json`, `vex/CVE-2024-4076.json` (Red Hat CSAF);
  `cve/` holds the MITRE records (upstream coords; not used for RPM correlation).
