# S16 — Cross-scheme PURL query: non-RPM package inherits an RPM/Storage-3 status — TC-5170

Reproduces the **original [TC-5170](https://redhat.atlassian.net/browse/TC-5170) symptom**: querying a
**non-RPM** PURL (OCI, Maven, …) returns a `product_status` whose version range / context belongs to an
**RPM under Red Hat Storage 3** — e.g. the ticket's `pkg:oci/golang@1.25` getting an rpm
`[3.0.0,4.0.0) scheme=rpm` range. Root cause: `get_product_statuses_for_purl` matched by base package
**name** without checking version **scheme** or product context.

## Data
`vex/CVE-2023-44487.json` (HTTP/2 Rapid Reset): `golang` `known_affected` in **Red Hat Storage 3**
(`cpe:/a:redhat:storage:3`), bare component → `product_status`. The correct discriminator is **product
identity** (is the SBOM Storage 3?) and **scheme** (rpm vs oci/maven) — never base name alone.

> **Synthetic advisory (by design).** Unlike the other scenarios (real Red Hat CSAF), this VEX is a small
> hand-crafted CSAF: a `golang` `product_version` branch `default_component_of red_hat_storage_3:golang.src`
> with `known_affected: [red_hat_storage_3:golang.src]`. That is the correct `product_status` shape and it is
> run-verified to fire, but the real CVE-2023-44487 CSAF is huge — synthetic keeps the scenario focused.

## VEX ↔ SBOM correlation

| SBOM | CPE on | pkg@version (scheme) | Matched VEX entry | Expected | Note |
|---|---|---|---|---|---|
| `sbom_golang_rpm_storage3` | describing/**root** | `golang@3.5.0` (rpm) | `golang` known_affected @ `cpe:/a:redhat:storage:3` (range `[3,4)`) | **affected** | positive control — in-context rpm; **coincidental** match: `3.5.0` falls in `[3,4)` only because component-major `3` == product-major `3`; a `5.x` would drop |
| `sbom_golang_oci` | none | `golang@1.25` (oci) | — (cross-scheme, not Storage 3) | **not_affected** | TC-5170 exact repro — oci must not inherit the rpm/Storage-3 status |
| `sbom_golang_maven` | none | `golang@3.5.0` (maven) | — (cross-scheme, not Storage 3) | **not_affected** | `3.5.0` *looks* in an rpm `[3,4)` range, but applying an rpm range to a Maven version is a category error |

### Reading the matrix
- **rpm_storage3** — the positive control. The SBOM is genuinely Red Hat Storage 3 (an rpm `golang` under
  `cpe:/a:redhat:storage:3` on the describing/root node) ⇒ **affected**. Note this is a **coincidental** pass:
  the `product_status` range derived from the `storage:3` CPE is `[3,4)`, and `golang@3.5.0` falls inside it
  only because the component major (`3`) happens to equal the product major (`3`); a `golang@5.x` here would
  silently drop. It proves the fix does not over-suppress a real in-context match, not that "any version" hits.
- **oci** — not Storage 3, and rpm↔oci is cross-scheme, so nothing should correlate ⇒ **not_affected**. This
  is the ticket's exact repro: a `pkg:oci/golang@1.25` must not inherit the Storage-3 rpm status.
- **maven** — not Storage 3, and rpm↔maven is cross-scheme ⇒ **not_affected**. The `3.5.0` version *looks*
  like it falls inside an rpm `[3,4)` range, but applying an rpm range to a Maven version is a category error;
  product identity + scheme decide, not the number.

The rpm_storage3-vs-{oci,maven} contrast (same base name `golang`, only scheme/product context differs)
isolates the cross-scheme name-only match: on a correct engine only the in-context rpm correlates, while the
non-RPM packages are **expected to leak per TC-5170** on whichever paths still match by name without checking
scheme or product context.

**Bug (TC-5170):** get_product_statuses_for_purl matches golang by base name without checking PURL scheme or product context, so a non-RPM golang inherits the Storage-3 rpm status.

## Files
- SBOMs: `sbom_golang_{oci,maven,rpm_storage3}.{cdx,spdx}.json`.
- Advisory: `vex/CVE-2023-44487.json` (bare `golang` known_affected under `cpe:/a:redhat:storage:3`).
