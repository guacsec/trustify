# S20 — CPE with version range (WAGO)

Demonstrates the most common CPE pattern in industrial CSAF advisories: a product CPE with version
ANY on a `product_version_range` branch, whose `vers:` name constrains the version, plus a separate
CPE with the exact fixed version. The firmware is `installed_on` the hardware via relationships.

## Data (WAGO, VDE-2025-081: CVE-2025-41700, CVE-2025-41738, CVE-2025-41739)

| branch | CPE | range / version | status |
|---|---|---|---|
| `product_version_range` | `cpe:2.3:o:wago:wago_os_linux:*:…` | `vers:semver/>=1.0.0\|<4.10.0` | `known_affected` (installed on CC100, PFC100, PFC200, …) |
| `product_name` | `cpe:2.3:o:wago:wago_os_linux:4.10.0:…` | — | `fixed` |
| `product_version_range` | `cpe:2.3:o:wago:wago_os_linux_hardened:*:…` | `vers:semver/>=1.0.0\|<4.10.0 (70)` | `known_affected` |
| `product_version` | `cpe:2.3:o:wago:wago_os_linux_hardened:4.10.0:…` | — | `fixed` |

The hardware products carry no CPEs. For relationships, only the component side (the firmware)
yields CPE assertions.

## Expected (SBOM × CVE) — matches `expected.json`

All SBOMs are synthetic: one device with its firmware as a component with a concrete CPE.

| SBOM | firmware CPE | all three CVEs | evidence |
|---|---|---|---|
| `pfc200_fw_4.8.9` | `wago_os_linux:4.8.9` | affected | range match, confidence 0.7 |
| `pfc200_fw_4.10.0` | `wago_os_linux:4.10.0` | fixed | exact version, confidence 0.8 — not in `[1.0.0,4.10.0)` |
| `cc100_hardened_4.8.9` | `wago_os_linux_hardened:4.8.9` | affected | range match; the vendor's `4.10.0 (70)` bound still compares |

## Files

- SBOMs: `sbom/*.cdx.json` (synthetic)
- Advisory: `vex/vde-2025-081.json` (WAGO CSAF, TLP:WHITE)
