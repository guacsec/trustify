# S18 — RHEL 8 curl "Not affected" overridden by a cross-product match (TC-5171 + TC-5730)

**Issue.** For `CVE-2022-32207`, Red Hat **explicitly marks RHEL 8 curl `known_not_affected`** in the VEX. But
the same CSAF lists curl as affected under **other products** (RHEL 9, JBoss Core Services, Software
Collections). Because the advisory's CPE isn't checked against the queried package, the RHEL 9 curl range
matches a RHEL 8 curl by name — **overriding the explicit RHEL 8 `not_affected`** and reporting it Critical.

## Data (real Red Hat CSAF `vex/CVE-2022-32207.json`)
```
known_not_affected:  cpe:/o:redhat:enterprise_linux:8            curl   ← RHEL 8 explicitly SAFE
fixed:               cpe:/o:redhat:enterprise_linux:9::baseos    curl@7.76.1-14.el9_0.5   (+ JBCS el7/el8, SCL)
```

## VEX ↔ SBOM correlation

Two axes: a **CPE-context** axis on RHEL 8 curl (which is `known_not_affected`) and a **version** axis on
RHEL 9 curl (the genuinely-affected product, fix `7.76.1-14.el9_0.5`).

| Axis | SBOM | CPE on | Installed `curl` | Matched VEX entry (CPE + status) | Expected | Engine today |
|---|---|---|---|---|---|---|
| CPE-context | `sbom_curl_rhel8_rootcpe` | describing/root | `7.61.1-34.el8` | `cpe:/o:redhat:enterprise_linux:8` — **known_not_affected** | **not_affected** | not_affected ✓ |
| CPE-context | `sbom_curl_rhel8_notaffected` | child OS node | `7.61.1-34.el8` | el8 **known_not_affected**; leaks to el9 **fixed** `7.76.1-14.el9_0.5` @ `cpe:/o:redhat:enterprise_linux:9::baseos` | **not_affected** | **affected** ✗ TC-5171/5730 |
| version | `sbom_curl_rhel9_belowfix` | child OS node | `7.76.1-10.el9_0.5` | el9 **fixed** `7.76.1-14.el9_0.5` | **affected** | affected ✓ |
| version | `sbom_curl_rhel9_atfix` | child OS node | `7.76.1-14.el9_0.5` | el9 **fixed** `7.76.1-14.el9_0.5` | **not_affected** | not_affected ✓ |
| version | `sbom_curl_rhel9_abovefix` | child OS node | `7.76.1-16.el9_0.5` | el9 **fixed** `7.76.1-14.el9_0.5` | **not_affected** | not_affected ✓ |

### Reading the matrix
- **curl_rhel8_rootcpe** — the product CPE is on the **describing/root** node (captured), so the CPE-context
  filter should **engage**: scope to `enterprise_linux:8`, honor the `known_not_affected`, and drop the el9
  match → **not_affected**.
- **curl_rhel8_notaffected** — same RHEL 8 curl, but the CPE sits on a **child** node (real RHEL layout) → not
  captured → the filter escape-hatches (**TC-5750**). The el9 `fixed` entry then matches the el8 curl by name
  (`7.61.1` < `7.76.1-14.el9_0.5`, dist-tag-blind), **overriding** the explicit el8 `known_not_affected` →
  leaks as affected (**TC-5171** CPE context not checked + **TC-5730** `known_not_affected` ignored). This is
  the only cell that fails on main.
- **curl_rhel9_{belowfix,atfix,abovefix}** — the genuinely-affected product, a lean **within-substream**
  version sanity: all three are on the fix's substream (`.el9_0.5`), so only the release moves (10/14/16 vs the
  fix `14`). Below → **affected**; at/above → **not_affected**. All correct on main: when curl is *genuinely*
  in the el9 product scope, `version_matches` engages properly. This isolates S18's bug to the cross-product
  bleed above — version handling itself is fine *within* the correct product. (The cross-**substream** guard —
  a build on a substream the VEX doesn't cover — is exercised by **S15** group B, not duplicated here.)

## Coupling
Two bugs at once: the CPE-context isn't checked (**TC-5171**) and the explicit `known_not_affected` is ignored
(**TC-5730**); the el8↔el9 comparison is **TC-5640**.

## Files
- SBOMs: `sbom_curl_{rhel8_notaffected,rhel8_rootcpe,rhel9_belowfix,rhel9_atfix,rhel9_abovefix}.{cdx,spdx}.json`.
- Advisory: `vex/CVE-2022-32207.json` (real Red Hat CSAF), stored xz-compressed.
