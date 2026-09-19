# S11 — Bare `known_affected` on the main stream (firefox)

Isolates a **version-less `known_affected`** on the GA stream while only sub-streams carry versioned
fixes. A bare `known_affected` means "affected, all versions" (standard §4.3.3/§8.1) → the main box is
affected; a patched sub-stream box is not.

## Data (CVE-2023-6135)
| stream | `firefox` statement |
|---|---|
| `enterprise_linux:8` (GA) | base `firefox` **`known_affected`** (bare, no version) |
| `enterprise_linux:8` (GA) | `firefox:flatpak` **module** `known_not_affected` (distinct component, §1.1/§8) |
| `rhel_eus:8.8` | `fixed 128.2.0-1.el8_8` |

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `firefox`) | stream | CVE-2023-6135 |
|---|---|---|
| `sbom_firefox_main_el8` (`115.15.0-1.el8`, base RPM) | el8 GA (`enterprise_linux:8`) | affected |
| `sbom_firefox_eus8.8_patched` (`128.2.0-1.el8_8`) | EUS 8.8 (`rhel_eus:8.8`) | not_affected |

- **main_el8** — the SBOM's firefox is the **base RPM** (no module qualifier), which matches the base
  `known_affected` → **affected**. The `firefox:flatpak` `known_not_affected` is a *different component*
  (module) and does not suppress it (§1.1/§8).
- **eus8.8_patched** — EUS 8.8 box at the EUS fix `128.2.0-1.el8_8` → **not_affected** (§3/§5). Its
  describing CPE (`rhel_eus:8.8`) matches its build — a model of §1.2 consistency.

## Files
- SBOMs: `sbom_firefox_main_el8.{cdx,spdx}.json`, `sbom_firefox_eus8.8_patched.{cdx,spdx}.json`.
- Advisory: `vex/CVE-2023-6135.json` (Red Hat CSAF).
