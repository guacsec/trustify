# S5 — Positive baseline: version decides (openssl on RHEL 8)

Isolates the **version check** on a single product/stream. Same product (`enterprise_linux:8`), same
package (`openssl`) — the only variable is the installed version vs the fix. Regression guard that a
correct engine keeps reporting a genuinely-affected build and drops a patched one.

## Data
`openssl` on RHEL 8, both CVEs `fixed` on the el8 stream at **`1:1.1.1k-9.el8_7`** (openssl is epoch 1,
single `1.1.1k` line). Affected = same-stream openssl **below** that build (standard §3, `purl_status`).

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `openssl`) | CVE-2022-4304 | CVE-2023-0215 |
|---|---|---|
| `sbom_openssl_el8_below-fix` (`1:1.1.1k-7.el8`) | affected | affected |
| `sbom_openssl_el8_at-fix` (`1:1.1.1k-9.el8_7`) | not_affected | not_affected |

- **below-fix** — release `7.el8` < `9.el8_7` → below the el8 fix → **affected**.
- **at-fix** — installed == fix → **not_affected**.

## Files
- SBOMs: `sbom_openssl_el8_below-fix.{cdx,spdx}.json`, `sbom_openssl_el8_at-fix.{cdx,spdx}.json`
- Advisories: `vex/CVE-2022-4304.json`, `vex/CVE-2023-0215.json` (Red Hat CSAF). `cve/` holds the MITRE
  records (upstream coords only; not used for RPM correlation).
