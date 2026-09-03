# S7 — CPE-only (purl-less) node must NOT inherit a package-scoped advisory (TC-5630)

A node identified by a **product CPE with no purl** and **no packages** must not be reported vulnerable by
an advisory that is scoped to **specific packages** under that product CPE. Matching the product CPE alone —
without checking that any affected package is actually present — is a **false positive**.

## Data
- SBOM `sbom_cpeonly_hummingbird` — one node: `cpe:2.3:a:redhat:hummingbird:1`, **no purl, no packages**.
- CVEs (`cve/`, CVE-JSON) — each marks **specific packages** under `cpe:/a:redhat:hummingbird:1` affected,
  **not** the product as a whole:
  - CVE-2026-12151 (undici/Node.js DoS) → `rust`, `nodejs25`, `nodejs24-main`, `nodejs26-main`
  - CVE-2026-16730 → `dbus-broker`
  - CVE-2026-33815 → `go-fdo-server` affected, `caddy` unaffected

## Expected (SBOM × CVE) — matches `expected.json`
All package-context SBOMs share the **same product CPE** (`cpe:/a:redhat:hummingbird:1`); the package
identity, its version, and whether it is actually **under** that CPE differ. Correlation must be
**package-granular within the CPE context**, not product-CPE-only, and must apply **version filtering**.

Verdicts below are the **expected** (correct) values; the **Engine today** column is what main actually
returns (confirmed by a local run — package-blind product-CPE rollup).

| SBOM | package (relative to `hummingbird:1` CPE) | CVE-2026-12151 (rust/nodejs) | CVE-2026-16730 (dbus-broker) | CVE-2026-33815 (go-fdo-server aff / caddy unaff) | Engine today |
|---|---|---|---|---|---|
| `sbom_cpeonly_hummingbird` | *(none — bare CPE, no packages)* | not_affected | not_affected | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_rust` | `rust` under the CPE (all-versions affected) | **affected** | not_affected | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_dbusbroker` | `dbus-broker` under the CPE | not_affected | **affected** | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_caddy` | `caddy` under the CPE (explicitly unaffected) | not_affected | not_affected | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_nodejs25` | `nodejs25` under the CPE (all-versions affected) | **affected** | not_affected | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_nodejs26_vuln` | `nodejs26-main` **26.4.0-1.hum1** (below fix) | **affected** | not_affected | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_nodejs26_fixed` | `nodejs26-main` **26.5.0-1.3.hum1** (at fix) | not_affected | not_affected | not_affected | all 3 → affected ✗ |
| `sbom_hummingbird_rust_detached` | `rust` present but **NOT under** the CPE (sibling) | not_affected | not_affected | not_affected | all 3 → affected ✗ |

(Every hummingbird-CPE SBOM returns all three CVEs affected today — so only the true-positive cells like
rust/nodejs25 → CVE-2026-12151 are coincidentally correct; the rest are false positives.)

- **cpe-only** — no affected package present → **not_affected** on all (product-CPE match alone must not report affected).
- **rust** / **dbus-broker** / **nodejs25** — the affected package IS present under the CPE and is affected for **all versions** (advisory `defaultStatus: affected`, no excluding `versions`) → **affected** for its CVE, not_affected for the others (positive controls; prove the match is real and package-scoped).
- **caddy** — present under the same CPE, but explicitly **unaffected** in CVE-2026-33815 → **not_affected** (package-level `known_not_affected` within the CPE; guards against product-CPE over-match).
- **nodejs26_vuln / nodejs26_fixed** — `nodejs26-main` is affected under `hummingbird:1` but **fixed at `26.5.0-1.3.hum1`** (the advisory marks `26.5.0-1.3.hum1 …*` unaffected). Installed **below** the fix → **affected**; installed **at/above** the fix → **not_affected**. Exercises `version_matches`/`rpmvercmp` (incl. `.hum1` disttag) **within** a CPE+packageName context — the only version-filtering cells in S7.
- **rust_detached** — the SBOM contains **both** the `hummingbird:1` CPE node and a `rust` package, but as **unrelated siblings** under a neutral describing root; `rust` is **not a descendant** of the CPE-bearing node → **not_affected**. Co-presence of a CPE and an affected package is **not** sufficient; the package must be **in the product's CPE context** (TC-5630 failure comment, point b).

> **Policy note (component-scoped).** S7 asserts a CPE-only node with **no packages** is `not_affected`
> (TC-5630 phase-2). This intentionally **overrides** `CORRELATION_STANDARD.md` §5's earlier
> *product-level rollup* wording ("a CPE-only node is affected if any component of that product is
> affected") — see the amended §5. The two cannot both hold; S7 encodes the component-scoped policy.
>
> **Format caveat.** The single-value `correct` map cannot distinguish "**no match**" from an explicit
> **`known_not_affected`** — both render as `not_affected` (e.g. `caddy` vs the cross-negatives). When
> validating, cross-check the real VEX/`/advisory` payload to confirm the *reason*, not just the verdict.

## The bug this guards against
The engine matches the **product CPE** (`hummingbird:1`) and reports **affected** on `/sbom/{id}/advisory`
and the `/vulnerability/{cve}` backlink, **ignoring that no affected package is present** — a false positive.

> **Engine today (confirmed by a local run):** on main the match is **fully package-blind** — *every*
> hummingbird-CPE SBOM reports **all three** CVEs affected, regardless of which package is present, whether
> it is under the CPE, or its version. So all cells except the genuine positives (e.g. `rust`/`nodejs25` for
> CVE-2026-12151) fail; the whole test is `#[ignore]` until the component-scoped + version-filtered policy is
> implemented (TC-5630).
(`/purl` and `/vulnerability/analyze` return nothing, since there is no purl to key on.) This means the SBOM
**list** count over-reports these CPE-only "matches"; surfacing them in the detail endpoints (the naive
TC-5630 direction) would institutionalize the false positive. The correct fix gates a CPE-only match on an
affected **package** actually being present (or on a genuine product-level affected statement — e.g. an OCI
image digest, TC-5650).

## Real-world reproducer (`sbom_opentofu_image`)
The exact SBOM from the TC-5630 bug report: **`registry.access.redhat.com/hi/opentofu:1.10.10`**
(CycloneDX 1.6, 676 components). Its only purl-less CPE node is `cpe:/a:redhat:hummingbird:1`
(`os:hummingbird@20251124`). None of the hummingbird advisories' affected packages (rust, nodejs*,
dbus-broker, go-fdo-server) are present among the image's 676 components — so the hummingbird CVEs match the
image **only** through that bare CPE. Component-scoped correlation must therefore report them **not_affected**;
on main the engine reports them **affected** (product-CPE rollup), which is the TC-5630 false positive at
real-world scale.

- Test `s7_cpeonly_opentofu_image` asserts the 3 shipped hummingbird CVEs (CVE-2026-12151, -16730, -33815) are
  not_affected on `/sbom/{id}/advisory`. Confirmed leaking on main.
- The bug report cites **16** such CVEs (list=44 vs detail=28, gap=16); reproducing all 16 needs the
  environment's 16 crafted hummingbird advisories. The 3 shipped here are the ones carrying an affected
  `cpe:/a:redhat:hummingbird:1` entry; the full 16 CVE ids are recorded in the ticket.

## Files
- SBOMs: `sbom_cpeonly_hummingbird.{cdx,spdx}.json` (bare CPE, no packages); the package-context set
  `sbom_hummingbird_{rust,dbusbroker,caddy,nodejs25}.{cdx,spdx}.json` (hummingbird CPE on the describing
  node + one package **contained under** it); the version-filtering pair
  `sbom_hummingbird_nodejs26_{vuln,fixed}.{cdx,spdx}.json` (`nodejs26-main` below/at the `26.5.0-1.3.hum1`
  fix); and `sbom_hummingbird_rust_detached.{cdx,spdx}.json` (neutral describing root; `hummingbird` CPE
  node and `rust` package as **unrelated siblings**, package NOT under the CPE). SPDX carries the CPE via
  `externalRefs` cpe23Type; CDX puts the CPE on `metadata.component` (or a component) and models
  containment via `dependencies`.
- Advisories: `cve/CVE-2026-12151.json`, `cve/CVE-2026-16730.json`, `cve/CVE-2026-33815.json` (CVE-JSON, CNA+ADP).
- Real-world SBOM: `sbom_opentofu_image.cdx.json.xz` (real `registry.access.redhat.com/hi/opentofu:1.10.10`, CycloneDX, 676 components; xz-compressed).
