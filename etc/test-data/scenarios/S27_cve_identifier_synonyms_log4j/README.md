# S27 — CVE identifiers are synonyms (log4j)

An `affected` entry identifies the software by `packageURL`, `collectionURL` + `packageName`, and a
CPE. The CVE schema's RFD "Supporting Package URLs" calls such identifiers synonyms of a single
software application: the entry's `versions` and `defaultStatus` apply to each of them.

## Data
`cve/CVE-2025-68161.json` — the official record from
[cvelistV5](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/68xxx/CVE-2025-68161.json),
unmodified: `pkg:maven/org.apache.logging.log4j/log4j-core` and `cpe:2.3:a:apache:log4j:*`, affected
in `[2.0-beta9, 2.25.3)` and `[3.0.0-alpha1, 3.0.0-beta3]` (maven), `defaultStatus: unaffected`.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed) | CVE-2025-68161 |
|---|---|
| `pkg:maven/…/log4j-core@2.24.3` | affected |
| `pkg:maven/…/log4j-core@2.25.3` | not_affected — the default |
| `cpe:2.3:a:apache:log4j:2.17.1` (no PURL) | affected — through the CPE synonym |
