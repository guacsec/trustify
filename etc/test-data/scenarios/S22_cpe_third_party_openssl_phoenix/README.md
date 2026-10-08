# S22 — Third-party component CPE inside firmware (Phoenix Contact)

Demonstrates a vendor advisory identifying a vulnerable third-party library (OpenSSL) by CPE. An SBOM
listing that library as a component of the device correlates through the library's CPE, even though
the vendor's own firmware carries no CPE.

## Data

**VDE-2025-109** (CVE-2024-2511, FL MGUARD 2xxx/4xxx):

| product | CPE | status |
|---|---|---|
| OpenSSL 3.0.0 | `cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*` | `known_affected` |
| OpenSSL 3.0.13 | `cpe:2.3:a:openssl:openssl:3.0.13:-:*:*:*:*:*:*` | `known_affected` |
| OpenSSL 3.0.14 | `cpe:2.3:a:openssl:openssl:3.0.14:-:*:*:*:*:*:*` | `fixed` |
| firmware 10.5.0 / 10.6.0 `installed_on` FL MGUARD hardware | — (no CPE) | `known_affected` / `fixed` |

Note the `update` attribute `-` (not applicable).

**VDE-2025-056** (PLCnext): firmware with a range CPE `installed_on` hardware with CPEs such as
`cpe:2.3:h:phoenix_contact:axc_f_2152:*:…`. The hardware is listed in both the `known_affected` and
the `fixed` combinations, so only the component side (the firmware) yields CPE assertions. The
hardware CPEs are not stored as assertions. No SBOM correlates with this advisory: its firmware range
uses the `generic` version scheme, which only supports equality.

## Expected (SBOM × CVE) — matches `expected.json`

| SBOM | OpenSSL CPE | CVE-2024-2511 | why |
|---|---|---|---|
| `mguard_4302_fw_10.6.0` | `openssl:3.0.14:-:…` | fixed | exact match |
| `mguard_4302_fw_10.6.0_any_update` | `openssl:3.0.14:*:…` | — | SBOM `update` ANY vs. advisory `-`: no match (strict superset). Typical for NVD-style CPEs from SBOM generators |
| `mguard_4302_fw_10.5.0` | `openssl:3.0.13:-:…` | affected | exact match |

## Files

- SBOMs: `sbom/*.cdx.json` (synthetic)
- Advisories: `vex/vde-2025-109.json`, `vex/vde-2025-056.json` (Phoenix Contact CSAF, TLP:WHITE)
