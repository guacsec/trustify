# CVSS Score Model

This document describes how CVSS scores are stored, selected, and surfaced
across the system. A single vulnerability can receive scores from multiple
advisories (CVE, CSAF, OSV), each carrying one or more CVSS versions
(v2.0, v3.0, v3.1, v4.0). The rules below govern which score appears in
each context.

## Storage

Scores are stored at two levels:

### Per-advisory scores (`advisory_vulnerability_score`)

Every advisory that reports a vulnerability may contribute CVSS scores.
These are stored in the `advisory_vulnerability_score` table, keyed by
`(advisory_id, vulnerability_id)`:

| Column           | Type       | Description                         |
|------------------|------------|-------------------------------------|
| `id`             | UUID       | Primary key (v7)                    |
| `advisory_id`    | UUID       | FK to `advisory`                    |
| `vulnerability_id` | String  | FK to `vulnerability`               |
| `type`           | ScoreType  | CVSS version (`2.0`, `3.0`, `3.1`, `4.0`) |
| `vector`         | String     | Raw CVSS vector string              |
| `score`          | f32        | Computed numeric base score         |
| `severity`       | Severity   | `none`, `low`, `medium`, `high`, `critical` |

Multiple rows can exist for the same `(advisory_id, vulnerability_id)` pair
when an advisory provides scores in multiple CVSS versions.

Multiple advisories can contribute scores for the same vulnerability. Their
rows coexist in the table, distinguished by `advisory_id`.

### Denormalized best score (`vulnerability` table)

The `vulnerability` table carries a single "best" score for quick filtering
and display:

| Column                     | Type       | Description                              |
|----------------------------|------------|------------------------------------------|
| `base_score`               | f64        | Best numeric CVSS score                  |
| `base_severity`            | Severity   | Severity derived from `base_score`       |
| `base_type`                | ScoreType  | CVSS version of the best score           |
| `authoritative_advisory_id`| UUID       | The advisory that contributed this score |

These columns are populated exclusively by the CVE loader (see below).

## Ingestion: How Each Loader Contributes Scores

### CVE loader

The CVE loader is the only loader that sets the vulnerability-level score.
It performs two operations:

1. **Per-advisory scores**: Parses `vectorString` fields from CNA and ADP
   metrics using `FromStr` and computes the numeric score via
   `calculated_base_score()`. All parsed scores are written to
   `advisory_vulnerability_score` via `ScoreCreator`.

2. **Vulnerability base score**: Selects the single "best" score from the
   CVE record using `extract_base_score()`, which applies these precedence
   rules:
   - CNA scores take priority over ADP scores (ADP is used only if CNA
     yields no parseable scores)
   - Higher CVSS versions take priority (v4.0 > v3.1 > v3.0 > v2.0)
   - Within the same version, the higher numeric score wins

   This best score is written to `vulnerability.base_score` /
   `base_severity` / `base_type` via the `VulnerabilityCreator` (which uses
   `ON CONFLICT ... UPDATE`).

3. **Authoritative advisory**: The CVE loader unconditionally sets
   `vulnerability.authoritative_advisory_id` to its own advisory ID via a
   direct `UPDATE` statement. This is not conditional — every CVE ingestion
   overwrites it.

### CSAF loader

The CSAF loader writes per-advisory scores to `advisory_vulnerability_score`
but **never touches** the vulnerability-level `base_score` or
`authoritative_advisory_id`. It passes `()` as vulnerability information to
`VulnerabilityCreator`, which triggers `ON CONFLICT DO NOTHING` — preserving
any existing base score set by a CVE.

### OSV loader

Same behavior as CSAF: writes per-advisory scores only, never touches the
vulnerability-level columns.

## Score Re-ingestion

`ScoreCreator` uses a **delete-and-replace** strategy: when an advisory is
re-ingested, all existing `advisory_vulnerability_score` rows for that
`advisory_id` are deleted before the new scores are inserted. This means
re-ingestion always reflects the current state of the advisory document.

Scores from other advisories are not affected — only the re-ingested
advisory's rows are replaced.

## Score Selection by API Context

Different API endpoints surface different scores depending on the use case:

### Vulnerability list / detail (`GET /v3/vulnerability[/{id}]`)

- **`base_score`** on `VulnerabilityHead`: the denormalized best score from
  the `vulnerability` table. This is the CVE-derived score.
- **`scores`** on `VulnerabilityDetails` (opt-in via `?scores=true`):
  returns all `advisory_vulnerability_score` rows from the **authoritative
  advisory only** (filtered by `authoritative_advisory_id`).
- **Per-advisory scores** on `VulnerabilityAdvisorySummary`: each advisory
  listed under the vulnerability includes its own `scores` array with all
  CVSS scores that advisory provides.

### Advisory list / detail (`GET /v3/advisory[/{id}]`)

Each `AdvisoryVulnerabilityHead` includes a `scores` array containing all
`advisory_vulnerability_score` rows for that specific advisory-vulnerability
pair. This shows the advisory's own assessment, which may differ from the
CVE's base score.

### SBOM severity counts

The raw SQL query for SBOM severity aggregation picks the **highest
severity** per `(sbom_id, vulnerability_id)` across **all advisories** that
affect that SBOM. It uses `DISTINCT ON` with a severity ranking
(`critical=5` down to `none=1`, missing scores as `unknown=0`).

This means the SBOM severity summary reflects the worst-case assessment
from any advisory, not just the authoritative CVE.

### SBOM detail status

Each `SbomStatus` entry includes `scores` from the specific advisory that
reported the affected status for that package. If Advisory A says a package
is affected and Advisory B also says it is affected, each status entry
carries its respective advisory's scores.

### PURL detail (`GET /v3/purl/{id}`)

`PurlStatus` includes all scores related to the vulnerability via
`find_related`, which returns scores from **all advisories** — not just
the one that reported the PURL status.

### Vulnerability analysis (`POST /v3/vulnerability/analyze`)

Returns `VulnerabilityHead` (with `base_score` from the vulnerability
table) plus `PurlStatus` entries (with scores from all advisories, as
described above).

## Upload Order Invariants

The system is designed so that the vulnerability-level `base_score` is
**order-independent** across different advisory types:

| Scenario              | Result                                      |
|-----------------------|---------------------------------------------|
| CVE only              | `base_score` reflects the CVE's best score  |
| CSAF then CVE         | `base_score` reflects CVE (CSAF never overwrites) |
| CVE then CSAF         | `base_score` reflects CVE (CSAF uses DO NOTHING) |
| OSV then CVE          | `base_score` reflects CVE                   |
| CVE then OSV          | `base_score` reflects CVE                   |
| CVE without scores    | `base_score` is NULL                        |

These invariants are verified by integration tests in
`modules/fundamental/src/vulnerability/endpoints/test.rs`
(`base_score_after_ingestion`).

## Edge Cases

### Multiple CVEs for the same vulnerability

If two different CVE records reference the same vulnerability ID (rare but
possible), the system is **last-write-wins**: the second CVE ingestion
overwrites `base_score` and `authoritative_advisory_id`. Both CVEs'
per-advisory scores coexist in `advisory_vulnerability_score`.

### CVE record without CVSS scores

Some CVE records lack metrics entirely, or contain only metrics without a
`vectorString` field. In this case `extract_base_score()` returns `None`
and the vulnerability's `base_score` is NULL. The `authoritative_advisory_id`
is still set (the CVE is authoritative regardless of whether it carries
scores).

### Invalid vector strings

When a CVE metric contains a `vectorString` that fails to parse, the
failure is reported as both a `tracing::warn!` log message and an
ingestion warning in the `IngestResult` API response. The metric is skipped
and does not contribute a score.

### CSAF and CVE disagreeing on score

A CSAF advisory may assign a different CVSS score to a vulnerability than
the CVE record does. Both scores are stored in
`advisory_vulnerability_score` under their respective advisory IDs. The
vulnerability-level `base_score` always reflects the CVE's assessment. The
SBOM severity counts use the highest severity from any advisory, so the
CSAF's score may influence SBOM-level severity even if it differs from the
CVE's score.

## Summary: Score Selection Matrix

| Context                      | Score source                              |
|------------------------------|-------------------------------------------|
| `vulnerability.base_score`   | CVE's best score (denormalized)           |
| Vulnerability detail scores  | Authoritative advisory's scores only      |
| Advisory detail scores       | That advisory's scores                    |
| SBOM severity counts         | Highest severity across all advisories    |
| SBOM status scores           | Reporting advisory's scores               |
| PURL status scores           | All advisories' scores for the vuln       |
