# 00015. Link vulnerability to its authoritative advisory and expose full scores on demand

Date: 2026-04-15

## Status

ACCEPTED

## Context

[ADR 00014](00014-advisory-vulnerability-scores.md) replaced average score fields with structured
score lists on advisory and vulnerability endpoints. Each vulnerability now carries a `base_score`
(type, score, severity) derived from the best available CVSS score during CVE ingestion.

However, `base_score` only stores the single best score. Clients that need the full set of CVSS
scores from the authoritative source (the CVE advisory that contributed the base score) cannot
retrieve them without scanning all linked advisories and guessing which one is authoritative. This
is both fragile and inefficient.

Additionally, the vulnerability table had no persistent link to the advisory that contributed its
base score. The relationship only existed implicitly: the CVE loader set `base_score` /
`base_type` / `base_severity` columns but did not record which advisory provided them.

## Decision

### New column: `authoritative_advisory_id`

A nullable `authoritative_advisory_id UUID` column is added to the `vulnerability` table. Together
with the vulnerability's own `id`, it forms a composite foreign key referencing
`advisory_vulnerability(advisory_id, vulnerability_id)`:

```sql
ALTER TABLE vulnerability
    ADD CONSTRAINT fk_vulnerability_authoritative_advisory
    FOREIGN KEY (authoritative_advisory_id, id)
    REFERENCES advisory_vulnerability(advisory_id, vulnerability_id)
    ON DELETE SET NULL (authoritative_advisory_id);
```

The composite FK is used instead of a simple FK to `advisory` because scores are stored per
(advisory, vulnerability) pair in `advisory_vulnerability_score`, not per advisory alone. The
composite FK guarantees that the referenced advisory-vulnerability relationship actually exists.

The `ON DELETE SET NULL (authoritative_advisory_id)` clause uses the PG15+ column-list syntax so
that only `authoritative_advisory_id` is set to NULL when the referenced `advisory_vulnerability`
row is deleted — the vulnerability's primary key `id` is never affected.

### Ingestion-time linking

The `authoritative_advisory_id` is set during CVE ingestion only. A CVE advisory is always the
authoritative source for its vulnerability, regardless of whether it carries CVSS scores. The CVE
loader unconditionally issues an `UPDATE` setting `authoritative_advisory_id` after creating the
advisory. Non-CVE ingestors (CSAF, OSV) never touch this column.

### Migration backfill

Existing data is backfilled during migration using the `type=cve` advisory label. When multiple
CVE advisories exist for the same vulnerability, the most recently modified one is chosen via
`DISTINCT ON ... ORDER BY modified DESC NULLS LAST`:

```sql
UPDATE vulnerability
SET authoritative_advisory_id = best.advisory_id
FROM (
    SELECT DISTINCT ON (av.vulnerability_id)
           av.vulnerability_id,
           a.id AS advisory_id
    FROM advisory a
    JOIN advisory_vulnerability av ON a.id = av.advisory_id
    WHERE a.labels->>'type' = 'cve'
    ORDER BY av.vulnerability_id, a.modified DESC NULLS LAST
) best
WHERE best.vulnerability_id = vulnerability.id;
```

### Optional `scores` query parameter on `GET /api/v3/vulnerability/{id}`

A new `scores` boolean query parameter is added to the vulnerability detail endpoint. When set to
`true`, the response includes a `scores` array containing all `ScoredVector` entries from the
authoritative advisory (the one identified by `authoritative_advisory_id`).

When `scores` is omitted or `false`, the `scores` field is absent from the response entirely.
When `scores=true` but no authoritative advisory is linked (non-CVE vulnerabilities), the field is
explicitly `null`. When the authoritative advisory exists but carries no CVSS scores, the field is
an empty array (`[]`).

No additional database queries are needed — the scores for all advisories of the vulnerability
are already fetched in `VulnerabilityDetails::from_entity`. The authoritative scores are simply
filtered from the existing result set using `authoritative_advisory_id`.

#### Example

`GET /api/v3/vulnerability/CVE-2023-1234?scores=true`

```json
{
  "identifier": "CVE-2023-1234",
  "base_score": { "type": "3.1", "score": 9.8, "severity": "critical" },
  "scores": [
    { "type": "3.1", "value": 9.8, "severity": "critical", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
    { "type": "2.0", "value": 10.0, "severity": "high", "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C" }
  ],
  "advisories": [...]
}
```

### Relationship to ADR 00014

ADR 00014 introduced `base_score` on `VulnerabilityHead` and removed legacy average fields. This
ADR builds on that foundation:

* `base_score` remains the primary score indicator (unchanged).
* `authoritative_advisory_id` records *which* advisory contributed the `base_score`, making the
  relationship explicit and queryable.
* The `scores` parameter provides access to the full score list from that same advisory, giving
  clients the complete CVSS picture (all versions, all vectors) without requiring them to iterate
  over all advisories.

## Consequences

* The `vulnerability` table gains a new nullable column and composite FK. The FK references a
  composite unique key on `advisory_vulnerability`, ensuring referential integrity.
* CVE ingestion performs one additional UPDATE per vulnerability to set `authoritative_advisory_id`.
  This is a single-row update by primary key and has negligible performance impact.
* Non-CVE ingestors (CSAF, OSV) are unaffected — they do not set `authoritative_advisory_id`.
* The `scores` query parameter is opt-in. Existing clients see no change in the default response
  shape. The field is only serialized when explicitly requested.
* Requires PostgreSQL 15+ for the `ON DELETE SET NULL (column_list)` syntax. The project already
  targets PostgreSQL 17.2, so this is not a new constraint.
