# S5a — VERS-based affected range for openssl (el8)

Validates that the correlation engine correctly handles CSAF `product_version_range` branches
with VERS expressions. This is the spec-compliant replacement for the implied-affected logic
that was removed from the engine.

## Data (CVE-2022-4304)

A synthetic CSAF advisory declares:
- `known_affected` for openssl versions below the fix, using a `product_version_range`
  branch with `vers:rpm/>=0|<1:1.1.1k-9.el8_7`
- `fixed` for the exact fix version `1:1.1.1k-9.el8_7`

## SBOMs

Two SBOMs (copied from S5):
- `sbom_openssl_el8_below-fix`: openssl `1:1.1.1k-7.el8` — below the fix version
- `sbom_openssl_el8_at-fix`: openssl `1:1.1.1k-9.el8_7` — at the fix version

## Expected (SBOM x CVE) — matches `expected.json`

| SBOM | CVE-2022-4304 |
|---|---|
| `sbom_openssl_el8_below-fix` | affected |
| `sbom_openssl_el8_at-fix` | not_affected |

The below-fix version (`1:1.1.1k-7.el8`) falls within the VERS range `>=0|<1:1.1.1k-9.el8_7`,
so the engine matches it as `known_affected`. The at-fix version (`1:1.1.1k-9.el8_7`) matches
the `fixed` assertion exactly, which resolves the affected status.

## Files

- SBOMs: `sbom_openssl_el8_below-fix.{cdx,spdx}.json`, `sbom_openssl_el8_at-fix.{cdx,spdx}.json`
- Advisory: `vex/CVE-2022-4304.json` (synthetic CSAF with VERS ranges)
