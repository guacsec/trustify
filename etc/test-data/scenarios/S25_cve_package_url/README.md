# S25 — CVE `packageURL`, `defaultStatus`, and `custom` versions (lodash, pytest)

CVE records (format 5.2) identifying the affected package by `packageURL`, which the spec requires
to be without a version: the versions are in `versions`, and all other versions have the
`defaultStatus`.

## Data
Official records from [cvelistV5](https://github.com/CVEProject/cvelistV5), unmodified:

- `cve/CVE-2026-2950.json` — lodash: `pkg:npm/lodash` (and three more packages) affected in
  `[4.17.23, 4.18.0)`, unaffected `4.18.0`, `defaultStatus: unaffected` (semver).
- `cve/CVE-2025-71176.json` — pytest: `pkg:pypi/pytest` affected in `[0, 9.0.2]` with the version type
  `custom` (unspecified), `defaultStatus: unknown`.

## Expected (SBOM × CVE) — matches `expected.json`
| SBOM (installed) | Verdict |
|---|---|
| `pkg:npm/lodash@4.17.23` | CVE-2026-2950 affected |
| `pkg:npm/lodash@4.18.0` | CVE-2026-2950 not_affected — listed |
| `pkg:npm/lodash@4.17.21` | CVE-2026-2950 not_affected — the default (`purl_default`) |
| `pkg:pypi/pytest@8.3.4` | CVE-2025-71176 affected — the `custom` range evaluated as Python versions (`purl_custom_range`) |
| `pkg:pypi/pytest@9.0.3` | — the default is `unknown`, which states nothing |
