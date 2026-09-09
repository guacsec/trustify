# S17 — Cross-product: RHEL 8 kernel matched to an OCP Go advisory (TC-5171)

**Issue.** `CVE-2023-24538` is a **Go `html/template`** vulnerability — it affects `go-toolset` /
container-tools only. But the Red Hat CSAF for it also carries **kernel** entries, because **OpenShift
Container Platform 4.13** bundles Go *and* kernel updates in one advisory. Because the CPE context isn't
checked, a plain **RHEL 8 kernel** name-matches the advisory's **OCP kernel** entry — even though the advisory
is scoped to OCP (not RHEL 8) and the CVE doesn't affect the kernel at all.

## Data (real Red Hat CSAF `vex/CVE-2023-24538.json`)
```
kernel      fixed  under cpe:/a:redhat:openshift:4.13::el9   kernel@5.14.0-284.16.1.el9_2          (OCP bundle, el9)
go-toolset  fixed  under cpe:/a:redhat:devtools:2023::el7    go-toolset-1.19-golang@1.19.9-1.el7_9  (the real component)
```
The kernel appears **only** under the OCP CPE — there is no `enterprise_linux:8` kernel entry anywhere.

## VEX ↔ SBOM correlation

Two axes: a **cross-product CPE-context** axis on the RHEL 8 kernel (the wrong-product entry) and a lean
**version** axis on go-toolset (the genuinely-affected product, fix `1.19.9-1.el7_9`).

| Axis | SBOM | CPE on | pkg@version | Matched VEX entry (product CPE + status) | Expected | Engine today |
|---|---|---|---|---|---|---|
| CPE-context | `sbom_kernel_rhel8` | child OS node | `kernel@4.18.0-553.el8_10` | none *(correct)*; buggy: kernel **fixed** `5.14.0-284.16.1.el9_2` @ `cpe:/a:redhat:openshift:4.13::el9` | **not_affected** | **affected** ✗ TC-5171/5640/5750 |
| CPE-context | `sbom_kernel_rhel8_rootcpe` | describing/root node | `kernel@4.18.0-553.el8_10` | none (el8 CPE captured; OCP entry out of scope) | **not_affected** | not_affected ✓ |
| version | `sbom_gotoolset_devtools_belowfix` | child OS node | `go-toolset-1.19-golang@1.19.4-1.el7_9` | go-toolset **fixed** `1.19.9-1.el7_9` @ `cpe:/a:redhat:devtools:2023::el7` | **affected** | affected ✓ |
| version | `sbom_gotoolset_devtools_atfix` | child OS node | `go-toolset-1.19-golang@1.19.9-1.el7_9` | go-toolset **fixed** `1.19.9-1.el7_9` | **not_affected** | not_affected ✓ |
| version | `sbom_gotoolset_devtools_abovefix` | child OS node | `go-toolset-1.19-golang@1.19.11-1.el7_9` | go-toolset **fixed** `1.19.9-1.el7_9` | **not_affected** | not_affected ✓ |

### Reading the matrix
- **kernel_rhel8** — the RHEL 8 kernel is not OCP and the CVE isn't a kernel bug → **not_affected**. The bug:
  it's reported affected because `4.18.0-553` sorts below the OCP kernel fix `5.14.0-284.16.1.el9_2` and the OCP
  CPE is never checked (triple-wrong: wrong product OCP≠RHEL8, cross-stream el8↔el9, wrong component). CPE on a
  **child** node → escape hatch (TC-5750). Only cell that fails on main.
- **kernel_rhel8_rootcpe** — same RHEL 8 kernel, product CPE on the **describing/root** node (captured). Same
  expected verdict (**not_affected**); tests whether the CPE-context filter **engages** so the OCP entry is
  scoped out. Contrast with `sbom_kernel_rhel8` (child-node CPE → leaks).
- **gotoolset_devtools_{belowfix,atfix,abovefix}** — the genuinely-affected product, a lean **within-substream**
  version sanity (all on the fix's `.el7_9` substream; only the version moves `1.19.4`/`1.19.9`/`1.19.11` vs fix
  `1.19.9`). Below → **affected**; at/above → **not_affected**; all correct on main. Confirms version handling
  is fine *within* the correct product, isolating the bug to the cross-product kernel leak. (The cross-substream
  guard lives in S15 group B, not duplicated here.)

## Coupling
Pure CPE-context failure (**TC-5171**) — the advisory's OCP/kernel entry must not attach to a RHEL 8 kernel.
Cross-stream comparison (el8↔el9) is **TC-5640**; child-node OS CPE not captured is **TC-5750**.

## Files
- SBOMs: `sbom_{kernel_rhel8,kernel_rhel8_rootcpe,gotoolset_devtools_belowfix,gotoolset_devtools_atfix,gotoolset_devtools_abovefix}.{cdx,spdx}.json`.
- Advisory: `vex/CVE-2023-24538.json` (real Red Hat CSAF), stored xz-compressed.
