# S4 — Wrong-product / CPE-context not checked (TC-5171)

**Component under test:** `pkg:rpm/redhat/python3-chardet@3.0.4-7.el8` (RHEL 8 OS package)
**SBOM:** `sbom_python3-chardet_el8.cdx.json` (CDX 1.6; el8 baseos node + python3-chardet)

## The bug
`python3-chardet` ships in **Red Hat Satellite** (a *different product*, built `.el7sat`).
The engine matches the RHEL-8 **OS** package to a **Satellite** advisory purely by package name,
ignoring that the advisory's context CPE is `cpe:/a:redhat:satellite:*` (product = `satellite`),
not `cpe:/o:redhat:enterprise_linux:8`. No CPE vendor/product check (TC-5171).

## The 3 reproducer CVEs (el8-OS = ABSENT from the advisory; only Satellite ships/fixes chardet)
| CVE | enterprise_linux:8 (VEX) | satellite (VEX) | Expected | Buggy engine |
|---|---|---|---|---|
| CVE-2018-11751 | absent (not tracked) | fixed (`…el7sat`) | **not_affected** | affected (satellite:6.x:el7) |
| CVE-2018-3258  | absent | fixed (`…el7sat`) | **not_affected** | affected (satellite:6.x:el7) |
| CVE-2019-0231  | absent | fixed (`…el7sat`) | **not_affected** | affected (satellite:6.x:el7) |

These are Satellite platform advisories that bundle `python3-chardet` as a dependency. The RHEL-8 OS
`python3-chardet` has **no** entry in the vulnerability at all → the CVE should not appear for this SBOM.
Observed on the buggy env: reported `affected` under a `cpe:/a:redhat:satellite` context.

## Why this is a *cleaner* TC-5171 than hummingbird
Satellite ships packages RHEL-8 OS does not security-track, so el8-OS is entirely absent → the whole CVE
is a false positive. (By contrast the `hummingbird` product bundles the same core libs as el8-OS —
curl/openssl/python — so el8 is usually genuinely affected and hummingbird only adds a *duplicate* row.)

## Files
- `sbom_python3-chardet_el8.cdx.json` — upload this.
- `vex/CVE-*.json` — Red Hat CSAF/VEX (the Satellite advisories to ingest). CSAF-only (no OSV for RPMs).
- `cve/CVE-*.json` — CVE Project (MITRE) records, reference.

## Reproduce
1. Ingest the 3 `vex/*.json`.
2. Upload `sbom_python3-chardet_el8.cdx.json`.
3. `GET /sbom/{id}/advisory` → BUG: python3-chardet listed `affected` for all 3 under a `satellite` context.
   Correct: none (el8-OS chardet is not in these vulnerabilities).
