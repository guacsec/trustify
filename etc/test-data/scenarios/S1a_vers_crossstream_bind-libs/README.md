# S1a — VERS-based cross-stream bind-libs

Validates that the correlation engine correctly handles per-stream VERS ranges across
multiple RHEL releases. Same SBOMs and expected results as S1.

## Difference from S1

S1 uses **real Red Hat CSAF** advisories. Those advisories have two data issues:

1. **Versionless PURLs for `known_not_affected` / `known_affected`** — e.g.,
   `red_hat_enterprise_linux_8:bind-libs` and `red_hat_enterprise_linux_10:bind-libs`.
   Per the PURL spec (ECMA-427), a versionless PURL identifies the *package*, not
   "all versions of the package". Asserting `known_not_affected` on a versionless PURL
   does not cover versioned components.

2. **Only exact `fixed` versions, no affected range** — e.g.,
   `AppStream-9.0.0.Z.EUS:bind-libs-32:9.16.23-1.el9_0.5.x86_64`. The advisory says
   *this specific build* is the fix, but does not declare which prior versions are
   affected. Determining that requires implied-affected inference, which is not
   spec-compliant.

S1a replaces those with **synthetic CSAF** advisories that use `product_version_range`
branches with VERS expressions bounded to each stream's version line:

| Stream | Version line | VERS boundary |
|--------|-------------|---------------|
| el8    | `9.11.x`    | `vers:rpm/>=0\|<32:9.12.0-0` (upper bound excludes el9) |
| el9    | `9.16.x`    | `vers:rpm/>=0\|<32:9.16.23-…` (upper bound = fix version) |
| el10   | `9.18.x`    | `vers:rpm/>=32:9.17.0-0` (lower bound excludes el9) |

By bounding each range to the stream's version line, the engine matches correctly
without needing CPE-scoped VERS or cross-stream inference.

## Data — advisory `bind-libs` statements (synthetic)

| CVE | el8 | el9 affected range | el9 fix | el10 |
|---|---|---|---|---|
| CVE-2022-0396 | `known_not_affected` | `vers:rpm/>=0\|<32:9.16.23-5.el9_1` | `32:9.16.23-5.el9_1` | (no entry) |
| CVE-2023-5517 | `known_not_affected` | `vers:rpm/>=0\|<32:9.16.23-1.el9_0.5` | `32:9.16.23-1.el9_0.5` | `known_affected` (`vers:rpm/>=32:9.17.0-0`) |
| CVE-2024-4076 | `known_not_affected` | `vers:rpm/>=0\|<32:9.16.23-1.el9_0.7` | `32:9.16.23-1.el9_0.7` | `known_affected` (`vers:rpm/>=32:9.17.0-0`) |

## Expected (SBOM x CVE) — matches `expected.json`

| SBOM (installed `bind-libs`) | CVE-2022-0396 | CVE-2023-5517 | CVE-2024-4076 |
|---|---|---|---|
| `sbom_bind-libs_el8.10` (`9.11.36-16.el8_10.8`) | not_affected | not_affected | not_affected |
| `sbom_bind-libs_el8.10_describing-cpe` (same build) | not_affected | not_affected | not_affected |
| `sbom_bind-libs_el9.0_below-fix` (`9.16.23-1.el9_0.6`) | affected | not_affected | affected |
| `sbom_bind-libs_el9.0_at-fix` (`9.16.23-1.el9_0.7`) | affected | not_affected | not_affected |
| `sbom_bind-libs_el9.0_above-fix` (`9.16.23-1.el9_0.8`) | affected | not_affected | not_affected |
| `sbom_bind-libs_el10` (`9.18.37-1.el10`) | not_affected | affected | affected |

## Files

- SBOMs: `sbom_bind-libs_*.{cdx,spdx}.json` (6, copied from S1)
- Advisories: `vex/CVE-2022-0396.json`, `vex/CVE-2023-5517.json`, `vex/CVE-2024-4076.json`
  (synthetic CSAF with per-stream VERS ranges).
  `cve/` holds the MITRE records (upstream coords only; not used for RPM correlation).
