# 00022. Correlation Engine: Evidence and Verdicts

Date: 2026-09-22

## Status

PROPOSED

## Context

Trustify ingests advisories (CSAF, CVE, OSV) and SBOMs (SPDX, CycloneDX) and
stores their data across normalized tables. Existing endpoints
(`/v3/vulnerability/analyze`, `/v3/purl/{key}`) expose vulnerability status
but lack:

- **Evidence provenance** — callers cannot see *which* assertions contributed
  to a status determination or *how* identity was established.
- **Confidence scoring** — all matches are treated equally regardless of
  match quality.
- **Digest-based correlation** — SBOM components carry checksums
  (`sbom_node_checksum`) that could establish exact identity matches, but
  this evidence dimension is not used today.

### What is evidence?

Evidence is a **link** between a component (left side) and a vulnerability
assertion from an advisory (right side). It records:

- **What**: the assertion status (affected, fixed, not_affected, ...)
- **How**: the match dimension that established the link (digest, purl, cpe)
- **How confident**: a numeric confidence score
- **Who**: which extractor produced this evidence
- **When**: timestamp of creation

Evidence is produced by extractors — pluggable processes that run different
matching strategies. Each extractor deposits evidence rows into a shared
table. The correlation API reads this evidence and resolves it into verdicts.

## Decision

### Evidence table

A single `correlation_evidence` table stores all evidence as component ↔
vulnerability links:

```sql
CREATE TABLE correlation_evidence (
    id                UUID PRIMARY KEY,
    sbom_id           UUID NOT NULL,
    node_id           TEXT NOT NULL,
    advisory_id       UUID NOT NULL,
    vulnerability_id  TEXT NOT NULL,
    status            assertion_status NOT NULL,
    match_dimension   match_dimension NOT NULL,
    confidence        DOUBLE PRECISION NOT NULL,
    extractor         TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

No dimension-specific identity columns. The evidence table records THAT a
link exists, not the identity data that established it — that data stays in
source tables (`sbom_node_checksum`, `base_purl`, `cpe`, etc.).

### Three-stage model

```
Data (DB tables)  →  Evidence (correlation_evidence)  →  Verdict (API)
```

- **Data**: Existing tables populated during ingestion.
- **Evidence**: Materialized links produced by extractors, stored in
  `correlation_evidence`.
- **Verdict**: Resolved status per (component, vulnerability), computed
  from evidence at query time.

### Extractors

Extractors are the processes that produce evidence. Each is identified by
a string ID (the `extractor` column). The first extractor is `digest` —
it matches SBOM component checksums against advisory-referenced hashes.
Later extractors add PURL and CPE matching.

### Match dimensions

| Dimension | Extractor matches via | Confidence band |
|-----------|----------------------|-----------------|
| Digest | `sbom_node_checksum` checksum equality | Highest |
| PURL | `base_purl` type/namespace/name + version range | Medium-High |
| CPE | `cpe` vendor/product match | Medium |

### Verdict status

```
affected | fixed | not_affected | under_investigation | none
```

`none` = no applicable evidence. Not the same as `not_affected`.

### Assertion status

```
affected | fixed | not_affected | under_investigation | recommended
```

`recommended` is a valid assertion status but not a valid verdict status.

### Incremental delivery

1. Foundation + Digest extractor
2. PURL extractor
3. CPE extractor
4. Multi-evidence resolution + verdict confidence
5. Materialized verdicts (background worker)

## Consequences

### Positive

- **Simple evidence model**: just a link table with metadata — no
  dimension-specific columns.
- **Pluggable extractors**: new match strategies just deposit rows.
- **Explainable results**: every verdict traces back to evidence rows
  with extractor, confidence, and timestamps.
- **Coexistence**: new endpoints coexist with existing `/v3/` paths.

### Negative

- **Two correlation paths during transition**.
- **Extractors must be run**: evidence doesn't appear automatically
  from ingestion (yet). Extraction is a separate step.
