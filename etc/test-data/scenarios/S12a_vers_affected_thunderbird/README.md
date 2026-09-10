# S12a — VERS-based affected range for thunderbird (synthetic)

Synthetic counterpart to S12. Uses spec-compliant `product_version_range` branches with VERS
expressions instead of versionless PURLs for `known_not_affected`.

## Data (CVE-2024-6602)

The advisory declares `known_affected` for all thunderbird versions below the fix using
`vers:rpm/>=0|<115.13.0-3.el8`, and `fixed` at `115.13.0-3.el8`.

Installed SBOM: `thunderbird@115.10.1-1.el8` (below the fix).

## Expected (SBOM x CVE) — matches `expected.json`

| SBOM | CVE-2024-6602 |
|---|---|
| `sbom_thunderbird_el8` (`115.10.1-1.el8`) | affected |

## Files

- SBOMs: copied from S12 (`sbom_thunderbird_el8.{cdx,spdx}.json`)
- Advisory: `vex/CVE-2024-6602.json` (synthetic CSAF with `product_version_range` + VERS)
