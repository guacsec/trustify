# Trustify API Changes: 0.4 → 0.5

## Overview

| | 0.4 (v2) | 0.5 (v3) |
|---|---|---|
| API version | v2 | v3 |
| Endpoints | 59 | 74 (v3) + 3 deprecated v2 |
| Schemas | 105 | 127 |

### Key migration concerns

1. **`/api/v2/` → `/api/v3/`** — all endpoint paths changed. Update every URL in your client.
2. **`total` must be explicitly requested** — paginated responses no longer include a total count by default. Pass `?total=true` to opt in; the `total` field is `null` otherwise.
3. **`GET sbom` response type changed** — now returns `SbomPackageSummary` instead of `SbomPackage` in `described_by`. Full package details remain available via `GET sbom/{id}/packages`.
4. **`POST vulnerability/analyze` response type changed** — `AnalysisResponse` → `AnalysisResponseV3`

Unless noted in the sections below, v3 endpoints are functionally equivalent to their v2 counterparts — only the URL prefix changed.

Three v2 endpoints are retained as deprecated in 0.5 for backward compatibility (see [Deprecated v2 Endpoints](#deprecated-v2-endpoints-retained-in-05)).

---

## New Endpoints

These endpoints exist in 0.5 but have no equivalent in 0.4.

### SBOM Groups (entire resource)

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/v3/group/sbom` | `listSbomGroups` | List SBOM groups |
| `POST` | `/api/v3/group/sbom` | `createSbomGroup` | Create a new SBOM group |
| `GET` | `/api/v3/group/sbom/{id}` | `readSbomGroup` | Read SBOM group information |
| `PUT` | `/api/v3/group/sbom/{id}` | `updateSbomGroup` | Update an SBOM group |
| `DELETE` | `/api/v3/group/sbom/{id}` | `deleteSbomGroup` | Delete an SBOM group |
| `PUT` | `/api/v3/group/sbom-assignment` | `bulkUpdateSbomGroupAssignments` | Bulk update SBOM group assignments |
| `PATCH` | `/api/v3/group/sbom-assignment` | `patchSbomGroupAssignments` | Partially update SBOM group assignments |
| `GET` | `/api/v3/group/sbom-assignment/{id}` | `readSbomGroupAssignments` | Get SBOM group assignments |
| `PUT` | `/api/v3/group/sbom-assignment/{id}` | `updateSbomGroupAssignments` | Update SBOM group assignments |

### SBOM Bulk Delete

| Method | Path | Operation | Description |
|---|---|---|---|
| `DELETE` | `/api/v3/sbom` | `deleteSboms` | Delete multiple SBOMs |

### AI Model Search (2 endpoints)

| Method | Path | Operation | Description |
|---|---|---|---|
| `GET` | `/api/v3/sbom/models` | `listAllModels` | Search for all AI models |
| `GET` | `/api/v3/sbom/{id}/models` | `listModels` | Search for AI models associated with an SBOM |

---

## Parameter Changes on Existing Endpoints

### New `total` query parameter (broad)

A `total` query parameter was added to **all paginated list endpoints**. When set, the response includes the total count of matching items. The `limit` parameter description was also updated: zero now means "return no items but still compute the total if requested."

Affected endpoints:
- `GET` advisory, analysis/component, analysis/component/{key}, analysis/latest/component, analysis/latest/component/{key}
- `GET` importer/{name}/report, license, license/spdx/license
- `GET` organization, product, purl, purl/base
- `GET` sbom, sbom/by-package, sbom/{id}/packages, sbom/{id}/related
- `GET` vulnerability, weakness

### SBOM-specific parameter additions

| Endpoint | New Parameters | Description |
|---|---|---|
| `GET /api/v3/sbom` | `group` | Filter by group IDs (multi-value) |
| `GET /api/v3/sbom` | `advisories` | Boolean opt-in flag (default `false`). When `true`, each SBOM in the response includes an `advisories` field with a severity-bucketed vulnerability count (e.g., `{"critical": 3, "high": 12}`). Does not filter results. |
| `POST /api/v3/sbom` | `group` | Assign to group on upload |
| `GET /api/v3/vulnerability/{id}` | `scores` | Include vulnerability scores |

---

## Structural Type Changes

### Pagination: `total` is now optional

In 0.4, `total` was a required `integer` field on all `PaginatedResults_*` types.
In 0.5, `total` is optional (`integer | null`) and only populated when the client passes `?total=true`.

Affects all paginated response types.

### `AdvisorySummary` — removed deprecated scoring fields

The inline `AdvisorySummary` type (in `PaginatedResults_AdvisorySummary`) dropped:
- `average_score` (f64, deprecated) — removed
- `average_severity` (string, deprecated) — removed

Only `vulnerabilities` remains as a required inline field.

### `VulnerabilitySummary` — stripped to head-only

In 0.4, `VulnerabilitySummary` was `VulnerabilityHead` + inline fields (`advisories`, `average_score`, `average_severity`).
In 0.5, it is just `VulnerabilityHead` — all inline summary fields were removed.

### `VulnerabilityHead` — added `base_score`

New optional field `base_score` (type `BaseScore`: `{score, severity, type}`).

### `PurlStatus` — reworked scoring model

| | 0.4 | 0.5 |
|---|---|---|
| Removed | `average_score`, `average_severity` | — |
| Added | — | `advisory` (required), `scores` (required, array of `BaseScore`), `version_range` |

Scoring moved from a single averaged value to an array of discrete `BaseScore` entries with type/severity/score.

### `VulnerabilityStatus` — added `remediations`

New required field `remediations` (array of `RemediationSummary`: `{category, data, details?, url?}`).

### `SbomPackage` — `licenses_ref_mapping` deprecated

The `licenses_ref_mapping` field is now marked deprecated. Licenses are pre-expanded at ingestion time via `expanded_license` / `sbom_license_expanded` tables; this field is always empty in 0.5.

### `GET sbom` list — response type changed

| | 0.4 | 0.5 |
|---|---|---|
| Response type | `PaginatedResults_SbomSummary` | `PaginatedResults_SbomSummary_SbomPackageSummary` |
| Item `described_by` | array of full `SbomPackage` | array of `SbomPackageSummary` (`{id, name, group?, version?}`) |
| New item field | — | `advisories` (optional, via `RequestedField`) |

The SBOM list response now returns a lighter `SbomPackageSummary` (no PURLs, CPEs, or license data) instead of the full `SbomPackage` for each `described_by` entry. Full package details are still available via `GET sbom/{id}/packages`.

### `POST vulnerability/analyze` — v3 response

| | 0.4 (`AnalysisResponse`) | 0.5 (`AnalysisResponseV3`) |
|---|---|---|
| Result type | `AnalysisResult` | `AnalysisResultV3` |
| Result fields | `details`, `warnings` | `details`, `warnings` |
| Details type | `AnalysisDetails` | `AnalysisDetailsV3` |

The v3 analysis response adds `AnalysisPurlStatus` and uses discrete `BaseScore` entries instead of averaged scores.

### `PaginatedResults_SbomSummary` — added optional `advisories`

The SBOM summary item type gained an optional `advisories` field (populated when `?advisories=true` is passed).

---

## Deprecated v2 Endpoints (retained in 0.5)

These three v2 endpoints are still present in the 0.5 spec but marked deprecated:

| Method | Path | Changes in 0.5 |
|---|---|---|
| `POST` | `/api/v2/purl/recommend` | operationId → `v2/recommend` |
| `GET` | `/api/v2/sbom` | operationId → `v2/listSboms`; added `total`, `group` params |
| `POST` | `/api/v2/vulnerability/analyze` | operationId → `v2/analyze` |

