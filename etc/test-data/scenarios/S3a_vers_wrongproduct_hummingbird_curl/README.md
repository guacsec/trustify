# S3a — Wrong product with VERS ranges: el8 curl vs hummingbird

VERS-augmented variant of [S3](../S3_wrongproduct_hummingbird_curl/). The original S3
relies on product context scoping (filtering by `relates_to_product_reference` CPE) which
the engine does not implement. This variant replaces the upstream Red Hat CSAF with
synthetic advisories that encode per-stream version boundaries using
`product_version_range` with VERS expressions. The disjoint version ranges make product
scoping unnecessary — each stream's assertions only match that stream's versions.

## Difference from S3

| Aspect | S3 (original) | S3a (this variant) |
|---|---|---|
| Advisories | Real Red Hat CSAF with versionless PURLs | Synthetic CSAF with `product_version_range` VERS |
| Product scoping | Required (el8 vs el10 vs hummingbird) | Not needed — VERS ranges are stream-disjoint |
| SBOMs | Identical | Identical (reused verbatim) |
| Expected verdicts | Identical | Identical |

## VERS boundaries

| CVE | el8 status | VERS range | Meaning |
|---|---|---|---|
| CVE-2024-2398 | `known_affected` | `vers:rpm/>=0\|<7.61.1-34.el8_10.2` | All el8 builds below fix |
| CVE-2024-2398 | `fixed` | `vers:rpm/>=7.61.1-34.el8_10.2` | All el8 builds at/above fix |
| CVE-2025-10148 | `known_not_affected` | `vers:rpm/>=0` | All versions |
| CVE-2025-10966 | `known_not_affected` | `vers:rpm/>=0` | All versions |
| CVE-2025-13034 | `known_affected` | `vers:rpm/>=0` | All versions (bare affected) |

## Expected (SBOM × CVE) — matches `expected.json`

| SBOM (installed `curl`) | CVE-2024-2398 | CVE-2025-10148 | CVE-2025-10966 | CVE-2025-13034 |
|---|---|---|---|---|
| `sbom_curl_el8` (`7.61.1-34.el8_10.11`) | not_affected | not_affected | not_affected | affected |
| `sbom_curl_el8_below-fix` (`7.61.1-34.el8_10.1`) | affected | not_affected | not_affected | affected |
| `sbom_curl_el8_el8cpe` (`7.61.1-34.el8_10.11`) | not_affected | not_affected | not_affected | affected |

- **CVE-2024-2398** — el8 fix at `.el8_10.2`: `.11` ≥ fix → fixed → not_affected; `.1` < fix → affected.
- **CVE-2025-10148 / -10966** — el8 `known_not_affected` for all versions.
- **CVE-2025-13034** — el8 `known_affected` for all versions (bare, no fix available).
- `sbom_curl_el8` and `_el8cpe` differ only in CPE placement → same verdicts.

## Files

- SBOMs: identical to S3 (same `curl` RPM versions and el8 CPE).
- CVE records: `cve/` — MITRE CVE 5.x records (semver, not used for RPM matching).
- Advisories: `vex/` — synthetic CSAF with VERS `product_version_range` branches.
