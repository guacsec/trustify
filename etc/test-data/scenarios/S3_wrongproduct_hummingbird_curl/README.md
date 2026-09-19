# S3 — Wrong product: an el8 box uses only el8 statements (curl)

Isolates **product scoping**. `curl` ships in both RHEL 8 and Red Hat Hardened Images
(`cpe:/a:redhat:hummingbird:1`) — a *different* product. An el8 box's verdict must come from the el8
statement only; a `hummingbird`/`jboss_core_services` statement is a different product (standard §5).

## Data — el8 `curl` statements
| CVE | el8 (`enterprise_linux:8`) | other products |
|---|---|---|
| CVE-2024-2398 | `fixed 7.61.1-34.el8_10.2` | el9, rhel_eus:9.2 fixes |
| CVE-2025-10148 | `known_not_affected` | `hummingbird:1` fixed `8.19.0-3.hum1` |
| CVE-2025-10966 | `known_not_affected` | `hummingbird:1` fixed `8.19.0-3.hum1` |
| CVE-2025-13034 | `known_affected` (bare) | `hummingbird:1` fixed `8.19.0-3.hum1` |

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed `curl`) | CVE-2024-2398 | CVE-2025-10148 | CVE-2025-10966 | CVE-2025-13034 |
|---|---|---|---|---|
| `sbom_curl_el8` (`7.61.1-34.el8_10.11`) | not_affected | not_affected | not_affected | affected |
| `sbom_curl_el8_below-fix` (`7.61.1-34.el8_10.1`) | affected | not_affected | not_affected | affected |
| `sbom_curl_el8_el8cpe` (`7.61.1-34.el8_10.11`) | not_affected | not_affected | not_affected | affected |

- **CVE-2024-2398** — el8 fix `.2`: `.11` ≥ fix → not_affected; `.1` < fix → affected.
- **CVE-2025-10148 / -10966** — el8 `known_not_affected` (§7); the `hummingbird` fix is a different product → not_affected.
- **CVE-2025-13034** — el8 `known_affected`, bare → affected for both builds (version-invariant, §8.1).
- `sbom_curl_el8` and `_el8cpe` differ only in CPE placement → same verdict.

## Files
- SBOMs: `sbom_curl_el8.{cdx,spdx}.json`, `sbom_curl_el8_below-fix.{cdx,spdx}.json`, `sbom_curl_el8_el8cpe.{cdx,spdx}.json`.
- Advisories: `vex/CVE-2024-2398.json`, `vex/CVE-2025-10148.json`, `vex/CVE-2025-10966.json`, `vex/CVE-2025-13034.json` (Red Hat CSAF); `cve/` MITRE records.
