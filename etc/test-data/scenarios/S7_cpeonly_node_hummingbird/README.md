# S7 — CPE-only (purl-less) node correlates by product CPE (hummingbird)

Isolates a node identified by a **CPE with no purl** (an OS/product node). It correlates by **product-CPE
identity** against advisory `affected[].cpes` (standard §1.1/§5) — not by any package/purl match.

## Data
- SBOM `sbom_cpeonly_hummingbird` — one node: `cpe:2.3:a:redhat:hummingbird:1`, **no purl**.
- CVEs (`cve/`, CVE-JSON format) — each lists `cpe:/a:redhat:hummingbird:1` as **affected**
  (in the CNA for CVE-2026-16730; in the Red Hat ADP enrichment for CVE-2026-12151 / -33815).

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (CPE-only node) | CVE-2026-12151 | CVE-2026-16730 | CVE-2026-33815 |
|---|---|---|---|
| `sbom_cpeonly_hummingbird` (`cpe:.../hummingbird:1`) | affected | affected | affected |

The node's CPE matches an `affected` `hummingbird:1` statement in each CVE → affected. For CVE-2026-33815
the product has both an `unaffected` and an `affected` component entry under that CPE; a CPE-only node
(no component granularity) is product-level → affected if any component under the CPE is affected.

## Files
- SBOM: `sbom_cpeonly_hummingbird.{cdx,spdx}.json` (SPDX carries the CPE via `externalRefs` cpe23Type).
- Advisories: `cve/CVE-2026-12151.json`, `cve/CVE-2026-16730.json`, `cve/CVE-2026-33815.json` (CVE-JSON, CNA+ADP).
