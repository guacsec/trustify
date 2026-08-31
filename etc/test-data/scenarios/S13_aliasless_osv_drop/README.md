# S13 — CVE-less advisory is still a real vulnerability (afire)

Isolates a vulnerability advisory with **no CVE alias** (GHSA/PYSEC/GO/RUSTSEC/MAL). It is still a real
vulnerability and must be reportable under its native id (standard §6).

## Data
`osv/GHSA-3227-r97m-8j95_real-no-cve.json` — real GitHub advisory, **no `aliases`**, affects
`pkg:cargo/afire` range `[0.2.1, 1.1.0)`. Installed SBOM: `pkg:cargo/afire@1.0.0` — inside the range.

## Expected (SBOM × id) — matches `expected.json`
| SBOM (installed) | GHSA-3227-r97m-8j95 |
|---|---|
| `sbom_afire_affected` (`cargo/afire@1.0.0`) | affected |

`afire 1.0.0 ∈ [0.2.1, 1.1.0)` → **affected**, reported under the native GHSA id (there is no CVE). The
golden is keyed by the GHSA id accordingly. (`_control_cve-injected.json` is the same record with one
synthetic CVE alias added — kept to show the cargo/semver correlation works; not ingested alongside the
real record — shared document_id.)

## Files
- SBOM: `sbom_afire_affected.{cdx,spdx}.json`.
- Advisories: `osv/GHSA-3227-r97m-8j95_real-no-cve.json` (the artifact); `osv/GHSA-3227-r97m-8j95_control_cve-injected.json` (contrast).
