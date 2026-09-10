# S2a — Component CPE matching for golang (data fix for S2)

Fixes the **data** problem from S2: the original advisory used a bare component name
(empty `product_identification_helper`), which the engine cannot match. S2a replaces
it with a **component-specific CPE** (`cpe:/a:golang:go`) and VERS ranges that target
golang versions 3.x as affected.

The **engine** limitation from S2 (same-version components in different products cannot
be distinguished without PURL qualifiers or product-scoped matching) remains tracked by S2.

## Data

Advisory `vex/CVE-2023-44487_golang.json`: targets `cpe:/a:golang:go` with three VERS ranges:
- `vers:semver/>=3.0.0|<4.0.0` → `known_affected`
- `vers:semver/<3.0.0` → `known_not_affected`
- `vers:semver/>=4.0.0` → `known_not_affected`

SBOMs carry component-level CPEs (`cpe:/a:golang:go:VERSION`) on each golang component.
Versions differ across SBOMs (in reality, different products ship different golang versions).

## Expected (SBOM x CVE) — matches `expected.json`
| SBOM (installed `golang`) | component CPE version | CVE-2023-44487 |
|---|---|---|
| `sbom_golang_storage3_inrange` | 3.5.0 | affected |
| `sbom_golang_rpm` | 1.20.6 | not_affected |
| `sbom_golang_rpm_inrange` | 1.21.0 | not_affected |
| `sbom_golang_oci` | 1.25 | not_affected |
| `sbom_golang_el8cpe_inrange` | 2.1.0 | not_affected |

- **storage3_inrange** — golang 3.5.0 falls in [3.0.0, 4.0.0) → **affected**.
- **rpm** — golang 1.20.6 falls in [0, 3.0.0) → **not_affected**.
- **rpm_inrange** — golang 1.21.0 (changed from 3.5.0 to avoid same-version ambiguity) → **not_affected**.
- **oci** — golang 1.25 → **not_affected**.
- **el8cpe_inrange** — golang 2.1.0 (changed from 3.5.0) → **not_affected**.

## Files
- SBOMs: `sbom_golang_{storage3_inrange,rpm,rpm_inrange,oci,el8cpe_inrange}.{cdx,spdx}.json`
- Advisory: `vex/CVE-2023-44487_golang.json`
