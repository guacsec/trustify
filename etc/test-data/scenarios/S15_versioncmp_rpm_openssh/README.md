# S15 — Same-type RPM version comparison (openssh on RHEL 8) — TC-5170 / TC-5640

The correct verdict for an `openssh` RPM is **version-decided against its own stream's fix**. This scenario
holds the product (`enterprise_linux:8`) and package (`openssh`) constant and varies three things
independently: **where the product CPE sits** (describing/root node vs a child OS node), **which
sub-stream** the build is on (a stream the VEX covers vs one it does not), and **the version** relative to
the fix. That isolates two distinct defects:

- **[TC-5170](https://redhat.atlassian.net/browse/TC-5170)** — when the CPE is on a *child* node (the escape
  hatch), the SBOM `product_status` paths match `openssh` by **name only** with no `version_matches`, so a
  build already at/past the fix is still reported `affected`.
- **[TC-5640](https://redhat.atlassian.net/browse/TC-5640)** — `rpmvercmp` ignores the dist tag, so a build
  on a sub-stream the VEX **does not cover** (`.el8_10`) is compared against a *different* sub-stream's fix
  (`.el8_8`) and wrongly correlates.

## Data
Real Red Hat CSAF `vex/CVE-2023-38408.json` (openssh, "RCE in ssh-agent PKCS#11"). It carries only `fixed`
status; versions below a fixed build are implicitly affected. The **main el8** BaseOS fix is
`openssh-0:8.0p1-19.el8_8` under `cpe:/o:redhat:enterprise_linux:8::baseos`. The VEX has entries for
el8_1/8_2/8_4/8_6/8_8 (and el9), **but nothing for the `el8_10` sub-stream**.

## VEX ↔ SBOM correlation

All SBOMs carry the same product CPE `cpe:/o:redhat:enterprise_linux:8::baseos` and a single `openssh` RPM.
The groups differ only in CPE placement (root vs child), sub-stream (dist tag), and version.

| Group | SBOM | CPE on | Installed `openssh` | Sub-stream in VEX? | Applicable fix | Expected | Engine today |
|---|---|---|---|---|---|---|---|
| **A** root / same stream | `sbom_openssh_rootcpe_el8_8_below-fix` | describing/root | `8.0p1-4.el8_8` | yes (`el8_8`) | `8.0p1-19.el8_8` | **affected** | affected ✓ |
| **A** | `sbom_openssh_rootcpe_el8_8_at-fix` | describing/root | `8.0p1-19.el8_8` | yes | `8.0p1-19.el8_8` | **not_affected** | not_affected ✓ |
| **A** | `sbom_openssh_rootcpe_el8_8_above-fix` | describing/root | `8.0p1-29.el8_8` | yes | `8.0p1-19.el8_8` | **not_affected** | not_affected ✓ |
| **B** root / different stream | `sbom_openssh_rootcpe_el8_10_below-fix` | describing/root | `8.0p1-4.el8_10` | **no** (`el8_10` absent) | — | **not_affected** | **affected** ✗ TC-5640 |
| **B** | `sbom_openssh_rootcpe_el8_10_at-fix` | describing/root | `8.0p1-19.el8_10` | no | — | **not_affected** | not_affected ✓ |
| **B** | `sbom_openssh_rootcpe_el8_10_above-fix` | describing/root | `8.0p1-29.el8_10` | no | — | **not_affected** | not_affected ✓ |
| **C** child / same stream | `sbom_openssh_el8_below-fix` | child OS node | `8.0p1-4.el8_8` | yes (`el8_8`) | `8.0p1-19.el8_8` | **affected** | affected ✓ |
| **C** | `sbom_openssh_el8_at-fix` | child OS node | `8.0p1-19.el8_8` | yes | `8.0p1-19.el8_8` | **not_affected** | **affected** ✗ TC-5170 |
| **C** | `sbom_openssh_el8_above-fix` | child OS node | `8.0p1-29.el8_8` | yes | `8.0p1-19.el8_8` | **not_affected** | **affected** ✗ TC-5170 |

### Reading the matrix
- **A (root CPE, covered stream)** — all correct today: when the describing CPE is *captured* on the root
  node, the path applies `version_matches`, so below→affected and at/above→not_affected. This is the
  positive control proving version filtering works when the CPE context is in scope.
- **B (root CPE, uncovered stream)** — the VEX says nothing about `el8_10`, so nothing should correlate. Yet
  `below` (release `4`) is reported **affected**: `rpmvercmp` ignores the `_10` vs `_8` dist tag and compares
  `4 < 19` against the `el8_8` fix (**TC-5640**). `at`/`above` (release `19`/`29`) happen to be ≥ `19`, so they
  don't leak — the bug only surfaces below the borrowed fix.
- **C (child CPE, covered stream)** — same builds and expectations as A, but with the CPE on a child OS node
  (the real RHEL layout). The describing-CPE filter never engages (escape hatch), so `product_status`
  matches by name with **no** `version_matches`: `at`/`above` both leak as **affected** (**TC-5170**).

The A-vs-C contrast (same versions, only CPE placement differs) isolates the effect of CPE capture on version
filtering; B isolates the dist-tag-blind cross-stream match.

## Files
- SBOMs (each: one `openssh` RPM under `cpe:/o:redhat:enterprise_linux:8::baseos`):
  - Group A — `sbom_openssh_rootcpe_el8_8_{below,at,above}-fix.{cdx,spdx}.json` (CPE on describing/root node).
  - Group B — `sbom_openssh_rootcpe_el8_10_{below,at,above}-fix.{cdx,spdx}.json` (root CPE; `el8_10`, absent from VEX).
  - Group C — `sbom_openssh_el8_{below,at,above}-fix.{cdx,spdx}.json` (CPE on a child OS node).
- Advisory: `vex/CVE-2023-38408.json` (real Red Hat CSAF; main el8 fix `8.0p1-19.el8_8`), stored xz-compressed.
