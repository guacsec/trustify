# S26 — CVE `cpeApplicability` (Linux kernel)

A CVE record whose `affected` entries name no identifier usable for matching (vendor/product
`Linux`, git and semver versions, `lessThanOrEqual: "5.4.*"` wildcards), but which states the
vulnerable kernel versions in `cpeApplicability`, the CPE Applicability Language adopted from NVD.

## Data
`cve/CVE-2024-26581.json` — the official record from
[cvelistV5](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/26xxx/CVE-2024-26581.json),
unmodified. Its `cpeApplicability` lists `cpe:2.3:o:linux:linux_kernel:*` in the ranges
`[5.4.262, 5.4.269)`, `[5.10.190, 5.10.210)`, `[5.15.124, 5.15.149)`, `[6.1.43, 6.1.78)`,
`[6.5, 6.6.17)`, `[6.5, 6.7.5)`, `[6.5, 6.8)` and from `6.4.8` on.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (kernel CPE version) | CVE-2024-26581 |
|---|---|
| `5.4.268` | affected — in `[5.4.262, 5.4.269)` |
| `5.4.269` | — |
| `6.4.8` | affected — from `6.4.8` on |
| `4.19.0` | — |
