# S8a — VERS-based affected range with epoch handling (openjdk)

Validates that CSAF `product_version_range` branches with VERS expressions correctly
handle RPM epoch prefixes. This is the spec-compliant replacement for S8, which relied
on the removed implied-affected logic.

## Data (CVE-2026-41254)

Synthetic CSAF advisory declares:

- `known_affected` via `product_version_range`: `vers:rpm/>=0|<1:1.8.0.502.b07-1.1.el8`
  (all versions below the fix, including epoch in the VERS bound)
- `fixed` at `java-1.8.0-openjdk@1.8.0.502.b07-1.1.el8` with `epoch=1`

Two SBOMs carry `java-1.8.0-openjdk@1.8.0.492.b09-1.el8` (below the fix):

| SBOM | Epoch in PURL? | Effective version | Result |
|------|---------------|-------------------|--------|
| `sbom_openjdk_no-epoch` | No | `1.8.0.492.b09-1.el8` (implicit epoch 0) | affected |
| `sbom_openjdk_with-epoch` | Yes (`epoch=1`) | `1:1.8.0.492.b09-1.el8` | affected |

Both versions are below the VERS upper bound `1:1.8.0.502.b07-1.1.el8` under RPM
version comparison, so both produce `affected`.

## Expected (SBOM × CVE) — matches `expected.json`

| SBOM | CVE-2026-41254 |
|------|---------------|
| `sbom_openjdk_no-epoch` | affected |
| `sbom_openjdk_with-epoch` | affected |

## Files

- SBOMs: `sbom_openjdk_no-epoch.{cdx,spdx}.json`, `sbom_openjdk_with-epoch.{cdx,spdx}.json`
  (copied from S8)
- Advisory: `vex/CVE-2026-41254.json` (synthetic, hand-crafted with VERS)
