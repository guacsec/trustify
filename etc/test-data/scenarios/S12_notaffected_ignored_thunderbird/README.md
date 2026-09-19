# S12 — `known_not_affected` must be honored (thunderbird)

Isolates the **authoritative negative**: an explicit `known_not_affected` for the installed package's
stream means not affected (standard §7), even when a sibling sub-stream `fixed` row would name-match.

## Data (CVE-2024-6602)
`enterprise_linux:8` (GA) thunderbird = **`known_not_affected`**; only sub-stream products are `fixed`
(`rhel_eus/aus/e4s/tus:8.x` at `115.13.0-3.el8_x`). Installed SBOM: `thunderbird@115.10.1-1.el8` — a GA
el8 build (`.el8` disttag), no describing CPE.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `thunderbird`) | CVE-2024-6602 |
|---|---|
| `sbom_thunderbird_el8` (`115.10.1-1.el8`, GA) | not_affected |

The box is el8 GA (via disttag); el8 GA is `known_not_affected` → **not_affected**. The sub-stream
`115.13.0` fixes are distinct products (§5) and must not flag this GA box. (`control/…_no-notaffected.json`
is the same advisory with the `known_not_affected` entries removed — kept to show the suppression is what
decides; not ingested alongside the real advisory — shared document_id.)

## Files
- SBOM: `sbom_thunderbird_el8.{cdx,spdx}.json`.
- Advisories: `vex/CVE-2024-6602.json` (Red Hat CSAF); `control/CVE-2024-6602_no-notaffected.json` (contrast).
