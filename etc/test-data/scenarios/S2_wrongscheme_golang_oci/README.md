# S2 — Product identity decides a bare component-in-product (golang)

Isolates the **discriminator for `product_status`**: a bare component under a product CPE is affected
because the SBOM **is that product** (CPE-context, standard §5) — **not** because its version falls in a
range and **not** by base name alone. Version/scheme is the wrong lever here (§4.5).

## Data
Advisory `vex/CVE-2023-44487_golang_barename.json`: `golang` `known_affected` in **Red Hat Storage 3**
(`cpe:/a:redhat:storage:3`), bare component (no purl) → `product_status`, all versions affected (§8.1).
(`control/…_purl.json` is the same record with golang's purl kept → a versioned `purl_status`; kept for
contrast, not ingested with the bug advisory — shared document_id.)

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `golang`) | describing CPE | CVE-2023-44487 |
|---|---|---|
| `sbom_golang_storage3_inrange` (rpm `@3.5.0`) | `storage:3` | affected |
| `sbom_golang_rpm` (rpm `@1.20.6-1.el8`) | none | not_affected |
| `sbom_golang_rpm_inrange` (rpm `@3.5.0`) | none | not_affected |
| `sbom_golang_oci` (`pkg:oci/golang@1.25`) | none | not_affected |
| `sbom_golang_el8cpe_inrange` (rpm `@3.5.0`) | `enterprise_linux:8` | not_affected |

- **storage3** — SBOM is Red Hat Storage 3 → CPE-context matches → **affected** (version irrelevant; bare KA).
- **rpm / rpm_inrange** — no product CPE → not Storage 3 → **not_affected**. Note `rpm_inrange` is `3.5.0`
  ("in [3,4)") yet still not_affected: version-in-CPE-range is a category error (§4.5); product identity decides.
- **oci** — not Storage 3, and rpm↔oci is cross-scheme (§3) → **not_affected**.
- **el8cpe_inrange** — RHEL 8 ≠ Storage 3 (§1.2/§5) → **not_affected**. A/B partner of `storage3` (same
  `golang@3.5.0`; verdict flips purely on the product CPE).

## Files
- SBOMs: `sbom_golang_{storage3_inrange,rpm,rpm_inrange,oci,el8cpe_inrange}.{cdx,spdx}.json`.
- Advisories: `vex/CVE-2023-44487_golang_barename.json`; `control/CVE-2023-44487_golang_purl.json` (contrast).
