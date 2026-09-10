# S5a — VERS-based affected range for openssl (el8)

Validates that the correlation engine correctly handles CSAF `product_version_range` branches
with VERS expressions. This is the spec-compliant replacement for the implied-affected logic
that was removed from the engine.

Same product, SBOMs, and CVEs as S5; the only difference is in the advisory data (see below).

## Difference from S5

S5 uses **real Red Hat CSAF** advisories that declare per-version `fixed` product IDs
(one product ID per patched build). The engine determines affected status by comparing the
installed version against the fix version listed in `purl_status`.

S5a replaces those with **synthetic CSAF** advisories that use `product_version_range`
branches with explicit VERS expressions (`vers:rpm/>=0|<1:1.1.1k-9.el8_7`) to declare
the `known_affected` range. The engine matches the installed version against the VERS
range directly, without relying on implied-affected inference.

## Data

Two synthetic CSAF advisories (one per CVE), each declaring:
- `known_affected` for openssl versions below the fix, using a `product_version_range`
  branch with `vers:rpm/>=0|<1:1.1.1k-9.el8_7`
- `fixed` for the exact fix version `1:1.1.1k-9.el8_7`

The `cve/` folder contains the upstream MITRE CVE records (same as S5, not used for
RPM correlation).

## SBOMs

Two SBOMs (copied from S5):
- `sbom_openssl_el8_below-fix`: openssl `1:1.1.1k-7.el8` — below the fix version
- `sbom_openssl_el8_at-fix`: openssl `1:1.1.1k-9.el8_7` — at the fix version

## Expected (SBOM x CVE) — matches `expected.json`

| SBOM | CVE-2022-4304 | CVE-2023-0215 |
|---|---|---|
| `sbom_openssl_el8_below-fix` | affected | affected |
| `sbom_openssl_el8_at-fix` | not_affected | not_affected |

The below-fix version (`1:1.1.1k-7.el8`) falls within the VERS range `>=0|<1:1.1.1k-9.el8_7`,
so the engine matches it as `known_affected`. The at-fix version (`1:1.1.1k-9.el8_7`) matches
the `fixed` assertion exactly, which resolves the affected status.

## Files

- SBOMs: `sbom_openssl_el8_below-fix.{cdx,spdx}.json`, `sbom_openssl_el8_at-fix.{cdx,spdx}.json`
- Advisories: `vex/CVE-2022-4304.json`, `vex/CVE-2023-0215.json` (synthetic CSAF with VERS ranges).
  `cve/` holds the MITRE records (upstream coords only; not used for RPM correlation).
