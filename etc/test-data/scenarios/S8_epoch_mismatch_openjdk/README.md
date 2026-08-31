# S8 — Epoch is metadata: verdict must not flip on it (java-1.8.0-openjdk)

Isolates **RPM epoch handling**. Epoch is metadata: a purl that omits `epoch=` must be evaluated with the
advisory's epoch, not treated as a mismatch (standard §3/§8). So the verdict must be **epoch-invariant**.

## Data
`java-1.8.0-openjdk` on RHEL 8 (epoch 1). All 3 CVEs are `fixed` on el8 at **`1:1.8.0.502.b07-1.1.el8`**.
Installed `1.8.0.492.b09-1.el8` → version `…492.b09` < `…502.b07` → below fix → affected.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `java-1.8.0-openjdk`) | CVE-2026-41254 | CVE-2026-46968 | CVE-2026-47010 |
|---|---|---|---|
| `sbom_openjdk_no-epoch` (purl without `epoch=`) | affected | affected | affected |
| `sbom_openjdk_with-epoch` (purl with `epoch=1`) | affected | affected | affected |

Both SBOMs are the same installed build below the el8 fix → **affected**. The only difference is the
`epoch=` qualifier, which must not change the verdict.

## Files
- SBOMs: `sbom_openjdk_no-epoch.{cdx,spdx}.json`, `sbom_openjdk_with-epoch.{cdx,spdx}.json`.
- Advisories: `vex/CVE-2026-41254.json`, `vex/CVE-2026-46968.json`, `vex/CVE-2026-47010.json` (Red Hat CSAF); `cve/` MITRE records.
