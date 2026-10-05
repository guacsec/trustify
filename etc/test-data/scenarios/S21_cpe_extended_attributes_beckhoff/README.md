# S21 — CPE 2.3 extended attributes (Beckhoff)

Demonstrates CPEs which pin the CPE 2.3 extended attributes `target_hw` (CPU architecture) and
`target_sw` (operating system), and the strict superset rule: an SBOM CPE leaving such an attribute
ANY does not match an advisory CPE that pins it.

## Data (Beckhoff, VDE-2025-092: CVE-2025-41726, CVE-2025-41727, CVE-2025-41728)

| product | CPE | status |
|---|---|---|
| MDP.dll (WinCE / WEC7), x86 | `cpe:2.3:a:beckhoff:MDP.dll:1.7.0.0:*:*:*:*:*:x86:*` | `fixed` |
| MDP.dll (WinCE / WEC7), arm32 | `cpe:2.3:a:beckhoff:MDP.dll:1.7.0.0:*:*:*:*:*:arm32:*` | `fixed` |
| IPC Diagnostics for Windows | `cpe:2.3:a:beckhoff:ipc_diagnostics_package:2.5.3:*:*:*:*:Windows:*:*` | `fixed` |

The vulnerable versions are only listed as `last_affected` (e.g. MDP.dll `1.2.4.0`), which is not
ingested yet. Therefore, this scenario only produces `fixed` verdicts.

## Expected (SBOM × CVE) — matches `expected.json`

| SBOM | component CPE | all three CVEs | why |
|---|---|---|---|
| `cx5020_wec7_x86` | `mdp.dll:1.7.0.0:…:x86:*` | fixed | `target_hw` equal (product compared case-insensitively) |
| `cx9020_wec7_arm32` | `mdp.dll:1.7.0.0:…:arm32:*` | fixed | distinct CPE from the x86 one |
| `cx_wec7_unknown_arch` | `mdp.dll:1.7.0.0:…:*:*` | — | SBOM `target_hw` is ANY, advisory pins it: no match (strict superset) |
| `c6030_ipc_diagnostics` | `ipc_diagnostics_package:2.5.3:…:windows:*:*` | fixed | `target_sw` equal |

## Files

- SBOMs: `sbom/*.cdx.json` (synthetic)
- Advisory: `vex/vde-2025-092.json` (Beckhoff CSAF, TLP:WHITE)
