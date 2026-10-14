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

## Correlation engine — official Red Hat VEX (`expected.json`)

The correlation scenario uses Red Hat's official VEX for CVE-2023-44487
(`../S16_crossscheme_purlquery_golang/vex/rh-cve-2023-44487.json.xz`, unmodified, downloaded
2026-10-09). The synthetic advisory above stays for the fundamental API tests.

In the official VEX, golang is `known_affected` in Red Hat Storage 3 with a **versionless** PURL
(`pkg:rpm/redhat/golang?arch=src`), as a `default_component_of` Storage 3
(`cpe:/a:redhat:storage:3`). That is the statement's product context. Red Hat also states fixed
builds for other products (`1.19.13-1.el9_2`, `1.19.13-1.module+el8.8.0+…`).

| SBOM | product context of `golang` | verdict | why |
|---|---|---|---|
| `storage3_inrange` | root component `cpe:/a:redhat:storage:3` | **affected** | `purl_any_version` in Storage 3, confidence 0.7 × 0.9 (root component, one hop) = 0.63 |
| `rpm` (`1.20.6-1.el8`) | RHEL 8, by the PURL's `distro=rhel-8.8` | none | the RHEL 8 fix specifies `rpmmod=go-toolset:rhel8:8080020231013004859:6b4b45d8`, which the installed PURL lacks; the versionless Storage 3 statement requires its product |
| `rpm_inrange` (`3.5.0`) | RHEL 8, by the PURL's `distro=rhel-8.8` | none | as `rpm`: the installed PURL lacks the module qualifier required by the RHEL 8 fix |
| `oci` | none | none | `pkg:oci/golang` is another package than `pkg:rpm/redhat/golang` |
| `el8cpe_inrange` | `cpe:/o:redhat:enterprise_linux:8::baseos` | none | RHEL is another product than Storage 3 (not comparable), so the versionless statement doesn't apply; the RHEL fixes are stated for AppStream (`cpe:/a:…`), which isn't comparable with the BaseOS CPE (`cpe:/o:…`) either, and reading a fix as `first_fixed` requires its product |

The matching-module controls `sbom_golang_rpm_module.{cdx,spdx}.json` add the exact
`rpmmod=go-toolset:rhel8:8080020231013004859:6b4b45d8` qualifier to the otherwise identical
`1.20.6-1.el8` fixtures and expect **fixed**. The previous fixed expectations for the
unqualified fixtures incorrectly applied a module-specific fix to an unspecified module.
These controls exercise qualifier matching alongside the existing product context checks.
