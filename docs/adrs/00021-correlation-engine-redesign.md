# 00021. Correlation Engine Redesign

Date: 2026-09-04

## Status

PROPOSED

## Context

The vulnerability correlation system determines which advisories affect which SBOMs by
matching advisory-side assertions (from CSAF, OSV, CVE, NVD documents) against SBOM
package identifiers. This is a core function of Trustify — the primary value proposition
for users is understanding "what vulnerabilities affect my software."

### Current Architecture

Correlation logic is scattered across five independent query-time SQL pathways in
`modules/fundamental/`, each with its own SQL and its own subset of matching strategies:

| # | Direction | Endpoint | purl | product | cpe | Code location |
|---|-----------|----------|:----:|:-------:|:---:|---------------|
| 1 | SBOM → vulns | `GET /v3/sbom/{id}/advisory` | ✓ | ✓ | ✓ | `sbom/model/details.rs` |
| 2 | SBOMs → severity counts | `GET /v3/sbom` (list) | ✓ | ✓ | ✓ | `sbom/model/raw_sql.rs` (`batch_severity_counts_sql`) |
| 3 | PURLs → vulns | `POST /v3/vulnerability/analyze` | ✓ | ✓ | | `vulnerability/service/mod.rs` |
| 4 | Vuln → SBOMs (reverse) | `GET /v3/vulnerability/{id}` | ✓ | ✓ | ✓ | `vulnerability/model/details/vulnerability_advisory.rs` |
| 5 | PURL → vulns | `GET /v3/purl/{key}` | ✓ | ✓ | | `purl/model/details/purl.rs` + `purl/service/mod.rs` |

Path 2 (batch severity counts) is completely separate SQL from Path 1 — different CTEs,
different function, operates on multiple SBOMs at once. Path 4 is the reverse direction
(vulnerability → affected SBOMs) with its own SQL for all three status tables. Paths 3
and 5 never query `cpe_status` — a coverage gap where CPE-only components are invisible.
A minor sixth path (`POST /v3/purl/recommend`) reuses Path 5's query code.

Three matching strategies are used across these paths:

| Strategy | Source table | Match key | Version check |
|----------|-------------|-----------|---------------|
| PURL-based | `purl_status` | `base_purl_id` | `version_matches()` PL/pgSQL function |
| Product name | `product_status` | bare `package` string (name only) | None (Path 1), applied (Path 3) — inconsistent |
| CPE identity | `cpe_status` | vendor+product (part='a') | `version_matches()` |

The five paths apply different subsets of these strategies and handle edge cases
inconsistently (e.g., Path 3 applies `version_matches()` to product_status while Path 1
does not). All paths that use `purl_status`/`product_status` apply a CPE context filter
via `sbom_describing_cpe`; the `cpe_status` path deliberately does not.

### Known Systemic Bugs

12 of 14 test scenarios in `modules/fundamental/src/correlation/test.rs` are `#[ignore]`d
due to fundamental bugs. A gist evaluation of all 18 scenarios (including 4 from open PRs)
shows 42 of 103 assertions failing (59% pass rate). The bugs trace to 9 distinct root
causes:

| Root cause | Tickets | Category |
|-----------|---------|----------|
| `product_status` matches by bare name — no PURL type check | TC-5170 | False positive |
| `product_status` matches without CPE product-scope check | TC-5171 | False positive |
| RPM dist tags (.el8 vs .el9) ignored in version comparison | TC-5640 | False positive |
| `product_status` does not apply `version_matches()` to the component version; the `product_version_range` stores the product version, not the component version, so the "naive fix" is semantically wrong | TC-5641 | False positive |
| `known_not_affected` status is never honored — queries only read `affected` | TC-5730 | False positive |
| OSV advisories without CVE alias are dropped — no advisory_vulnerability created | TC-5731 | False negative |
| Bare `known_affected` (no version range) creates no matchable row | TC-5732 | False negative |
| RPM epoch ignored by `rpmver_cmp` PL/pgSQL function | TC-5733 | Latent |
| Child-node CPEs not included in `sbom_describing_cpe` | TC-5750 | False positive |

### Current Performance

All correlation is computed at query time via complex multi-CTE SQL. Benchmarks from a
prototype in-memory engine (PR #2528) show the SQL path takes 57–434ms per request
depending on SBOM size, with 3.6–24x speedups achievable via in-memory matching.

### CSAF Spec Analysis

The `product_status.package` matching path is not endorsed by the CSAF v2.0 specification
for automated matching. The spec provides `product_identification_helper` with PURL, CPE,
and hashes as machine-matchable identifiers. The `name` field on `full_product_name_t` is
explicitly described as "human-readable." CSAF test 6.2.16 flags products without a
`product_identification_helper`.

The `sbom_describing_cpe` mechanism assumes SBOMs carry CPEs identifying their product
(e.g., "this SBOM is for RHEL 8"). In practice, most non-Red-Hat SBOMs lack describing
CPEs. The current fallback ("no describing CPEs → match against everything") creates
false positives — the exact opposite of what the filter intends.

## Decision

### Replace with a centralized, spec-oriented correlation module

Create a new `modules/correlation/` crate that:

1. **Matches on component identity only** using three spec-endorsed dimensions:
   PURL, CPE identity, and digest
2. **Drops product_status name matching** — not spec-valid for automated correlation
3. **Drops describing CPE scoping** — doesn't work for most data; product scoping is
   the user's responsibility via labels, groups, or external tooling
4. **Persists materialized results** in new database tables
5. **Records match evidence** so users can inspect why a match was made
6. **Uses in-memory indexes** for the hot matching path, with DB persistence for results
7. **Provides configurable knobs** via a policy table and CLI args
8. **Tracks correlation progress** via an inbox queue pattern

### Matching Dimensions

Three dimensions, all operating on component identity without product scoping:

**PURL matching (confidence: 0.9)** — the primary path for CSAF+PURL and OSV data.
Matches by `base_purl_id` with:
- PURL type enforcement (an RPM version range cannot match a golang PURL)
- Version comparison using the version scheme appropriate for the PURL type
- Unbounded version ranges match all versions (fixes bare `known_affected`)

No dist-tag stream isolation: if an advisory's version range catches a package from a
different stream via standard RPM comparison, that match stands. Stream scoping is the
advisory's responsibility (via precise version ranges or separate assertions per stream),
not the engine's — consistent with the decision to match on component identity only.

**Known gap — source-to-binary PURL mismatch:** An advisory referencing a source RPM
(e.g., `pkg:rpm/redhat/kernel?arch=src`) will not match an SBOM containing the binary
RPM (e.g., `pkg:rpm/redhat/kernel-core@...?arch=x86_64`) — these have different
`base_purl_id`s, no shared digest, and CPE matching is too coarse. The join between
source and binary only exists through SBOM relationships (SPDX `GENERATED_FROM`) or
build-system metadata (srpm→binary mapping). A relationship-based matching dimension
could address this but is out of scope for the initial engine.

**CPE identity matching (confidence: 0.8)** — for CVE/NVD data and CSAF advisories
that identify components by CPE. Matches by vendor+product (part='a') with version
comparison using `COALESCE(cpe_version, package_version)` for the SBOM side.

**Digest matching (confidence: 1.0)** — the strongest possible match per spec.
Exact hash-value lookup with no version comparison needed. Requires ingestor extension
to extract `product_identification_helper.hashes` from CSAF documents (prerequisite work).
Confidence may be adjusted in the future based on SBOM trust signals (e.g., whether the
SBOM is signed) — the policy model should leave space for this without implementing it
in the initial version.

### Status Resolution

All VEX statuses are honored, not just `affected`. When multiple assertions exist for the
same `(sbom_node, vulnerability)`:

1. `not_affected` from any advisory suppresses `affected` (configurable)
2. `fixed` suppresses `affected` (configurable)
3. `under_investigation` surfaces as-is
4. `affected` is the default when no suppression applies

### Correlation State and Work Queue

A single `correlation_state` table serves as both the work queue (workers poll
for `pending` rows) and the entity-level state tracker (API/UI reads the current
status). One row per entity — no separate inbox table.

| Column | Type | Notes |
|--------|------|-------|
| entity_type | correlation_entity_type | PK (composite) |
| entity_id | UUID | PK (composite) |
| status | correlation_state_status | `pending`, `processing`, `completed`, `failed` |
| error_message | TEXT | nullable — failure reason |
| started_at | TIMESTAMPTZ | nullable — when processing began |
| completed_at | TIMESTAMPTZ | nullable — when processing finished |
| correlated_as_of | TIMESTAMPTZ | nullable — advisory landscape timestamp at start of last run |
| trigger_type | correlation_trigger | nullable — what caused the last run |
| matches_found | INT | nullable — matches produced by last run |
| updated_at | TIMESTAMPTZ | last state transition |

When a document is ingested, the ingestor UPSERTs this row to `pending` in the
same transaction — same pattern as `record_change()` today. When an entity is
re-queued (e.g., because a new advisory affects it), the UPSERT resets the status
to `pending` regardless of current state.

The existing `SbomSummary` and `AdvisoryHead` response models include a
`correlation_status` field populated via a LEFT JOIN — no modification to the
core `sbom` or `advisory` tables.

#### SBOM-centric re-evaluation

All matching is SBOM-centric: a `pending` row means "re-evaluate all correlations
for this SBOM." The worker deletes existing matches for that SBOM, re-correlates
from scratch against the full `AdvisoryIndex` (which excludes deprecated
advisories), resolves statuses across all advisory assertions, and persists the
result.

This guarantees correctness for status resolution — the `effective_status` of a
`(sbom_node, vulnerability)` depends on assertions from *all* advisories (e.g.,
A1 says `affected`, A2 says `not_affected`). Processing one advisory in isolation
cannot compute the correct effective status.

#### Keeping correlations fresh

The ingestor marks the ingested entity as `pending` (in the same transaction as
the document insert). Workers handle the rest in two phases:

| Event | Ingestor action | Worker action |
|-------|----------------|---------------|
| New SBOM | UPSERT SBOM to `pending` | Re-evaluate SBOM against all advisories |
| New advisory | UPSERT advisory to `pending` | Fan-out: find affected SBOMs, UPSERT them to `pending` |
| Advisory deprecated | UPSERT advisory to `pending` | Fan-out: find SBOMs with matches against it, UPSERT to `pending` |
| Advisory deleted | CASCADE removes matches; UPSERT advisory to `pending` | Fan-out: find affected SBOMs, UPSERT to `pending` |
| Manual re-correlation | — | UPSERT specific SBOMs or all SBOMs to `pending` |

**Phase 1 — Advisory fan-out.** When a worker claims an advisory entry, it runs a
coarse DB query to identify affected SBOMs:

```sql
-- SBOMs containing PURLs referenced by this advisory
SELECT DISTINCT spr.sbom_id
FROM purl_status ps
JOIN versioned_purl vp ON vp.base_purl_id = ps.base_purl_id
JOIN qualified_purl qp ON qp.versioned_purl_id = vp.id
JOIN sbom_node_purl_ref spr ON spr.qualified_purl_id = qp.id
WHERE ps.advisory_id = $1
UNION
-- SBOMs containing CPEs referenced by this advisory
SELECT DISTINCT scr.sbom_id
FROM cpe_status cs
JOIN cpe ac ON cs.cpe_id = ac.id
JOIN cpe sc ON sc.vendor = ac.vendor AND sc.product = ac.product AND sc.part = 'a'
JOIN sbom_node_cpe_ref scr ON scr.cpe_id = sc.id
WHERE cs.advisory_id = $1
```

This is intentionally coarse — it matches by identifier but does not check version
ranges. Over-enqueuing is safe (the re-evaluation produces no matches if versions
don't overlap); missing SBOMs is not. The worker UPSERTs the affected SBOMs to
`pending` and marks the advisory `completed`.

**Phase 2 — SBOM re-evaluation.** Workers claim pending SBOM entries and perform
the full delete-and-rebuild matching described under
[SBOM-centric re-evaluation](#sbom-centric-re-evaluation).

#### Consistency during re-evaluation

The matching computation happens in memory (no transaction held). Results are then
swapped atomically in a short transaction:

```sql
BEGIN;
  DELETE FROM correlation_match WHERE sbom_id = $1;
  -- CASCADE removes correlation_evidence rows
  INSERT INTO correlation_match ... (new_matches);
  INSERT INTO correlation_evidence ... (new_evidence);
  UPDATE correlation_state
    SET status = 'completed', completed_at = now(), matches_found = $2;
COMMIT;
```

PostgreSQL MVCC guarantees that other connections see either all-old or all-new
matches — never a partial state. While the worker is computing (before the swap),
the old matches remain visible. After COMMIT, the new results replace them
atomically.

For a brand-new SBOM (no previous matches), `correlation_state.status = pending`
and the API returns "no correlation data yet" — also consistent.

#### Staleness detection

Between an advisory being ingested and the fan-out completing, affected SBOMs
still show `status = completed` with results that don't include the new advisory.
Their state is internally consistent but potentially stale.

To make this visible, `correlation_state` tracks a `correlated_as_of` timestamp
(set at the start of re-evaluation). A separate system-level value tracks the
timestamp of the last advisory change. The API includes both in SBOM responses:

- `correlation_status: completed`
- `correlated_as_of: 2026-09-07T10:00:00Z`
- `advisories_changed_at: 2026-09-07T10:05:00Z` ← newer → results may be stale

The UI can compare these to show a "results may not reflect recent advisories"
indicator, even before the fan-out identifies which specific SBOMs are affected.

Additionally, the API exposes the count of pending/processing advisory entries in
`correlation_state`. The UI can show "3 advisories being processed — some
correlation results may be incomplete" at the system level, giving users immediate
visibility that work is in progress.

#### Deduplication

Because state is per-entity (not per-event), concurrent re-queue requests
naturally deduplicate: if an SBOM is already `pending`, the UPSERT is a no-op.
If it's `processing`, the UPSERT resets it to `pending` so it gets re-evaluated
after the current run completes.

#### Multi-worker concurrency

Workers claim rows using `SELECT FOR UPDATE SKIP LOCKED`, allowing multiple
processors to run safely in parallel — even across different pods or hosts:

```sql
BEGIN;
SELECT * FROM correlation_state
WHERE status = 'pending'
ORDER BY updated_at
LIMIT $batch_size
FOR UPDATE SKIP LOCKED;
-- mark claimed rows as 'processing'
-- ... run matching pipeline ...
-- mark rows as 'completed' or 'failed'
COMMIT;
```

Workers can process items individually or in configurable batches. On crash or
timeout, the transaction rolls back and rows return to `pending` automatically.

#### Read-only replica usage

Matching reads (loading advisory/SBOM indexes, hydrating results) use the **RO
replica** for read scaling. State updates, match persistence, and evidence writes
use the **RW connection**. This accepts that a just-ingested document may not be
visible on the replica for a few seconds — the worker retries on the next poll
cycle if the entity is not yet visible.

### Database Schema

All fixed value sets use PostgreSQL ENUMs with `DeriveActiveEnum`:

```sql
CREATE TYPE correlation_entity_type AS ENUM ('sbom', 'advisory');
CREATE TYPE correlation_state_status AS ENUM ('pending', 'processing', 'completed', 'failed');
CREATE TYPE correlation_trigger AS ENUM ('sbom_ingested', 'advisory_ingested', 'full_rebuild', 'manual');
CREATE TYPE correlation_status AS ENUM ('affected', 'not_affected', 'fixed', 'under_investigation');
CREATE TYPE match_dimension AS ENUM ('purl', 'cpe_identity', 'digest');
CREATE TYPE evidence_source AS ENUM ('purl_status', 'cpe_status');
```

`correlation_state` is defined above in the [Correlation State and Work Queue](#correlation-state-and-work-queue)
section. It serves as both work queue and run metadata — only the latest run per
entity is tracked, so no separate `correlation_run` table is needed and no
retention policy is required.

**`correlation_match`** — materialized result per (node, vuln, advisory):

| Column | Type | Notes |
|--------|------|-------|
| id | UUID (v7) PK | |
| sbom_id | UUID FK → sbom | CASCADE |
| node_id | TEXT | sbom_package.node_id |
| advisory_id | UUID FK → advisory | CASCADE |
| vulnerability_id | TEXT FK → vulnerability | |
| effective_status | correlation_status | after precedence resolution |
| match_dimension | match_dimension | which matcher produced this |
| confidence | REAL | 0.0–1.0 |
| created_at | TIMESTAMPTZ | |
| UNIQUE | | (sbom_id, node_id, advisory_id, vulnerability_id) |

**`correlation_evidence`** — provenance for each match:

| Column | Type | Notes |
|--------|------|-------|
| id | UUID PK | |
| correlation_match_id | UUID FK → correlation_match | CASCADE |
| dimension | match_dimension | |
| source | evidence_source | which advisory-side table |
| source_row_id | UUID | row ID in source table |
| status | correlation_status | raw status from the advisory |
| description | TEXT | e.g., "PURL match: pkg:rpm/redhat/curl@1.2.3" |
| sbom_identifier | TEXT | PURL, CPE, or hash from the SBOM side |
| version_scheme | TEXT | nullable |
| sbom_version | TEXT | nullable |
| range_low | TEXT | nullable |
| range_high | TEXT | nullable |
| version_matched | BOOLEAN | nullable |

**`correlation_policy`** — configurable matching knobs:

| Column | Type | Default | Purpose |
|--------|------|---------|---------|
| id | UUID PK | | |
| name | TEXT UNIQUE | 'default' | |
| ecosystem | TEXT | null | nullable — when set (e.g., `rpm`, `maven`), this policy overrides the global default for that ecosystem |
| purl_type_strict | BOOLEAN | true | require PURL type match |
| not_affected_suppresses | BOOLEAN | true | not_affected beats affected |
| fixed_suppresses | BOOLEAN | true | fixed beats affected |
| digest_matching | BOOLEAN | true | enable hash-based matching |

The engine resolves the most specific policy for a given PURL type: an ecosystem-scoped
policy (where `ecosystem` matches the PURL type) takes precedence over the global
default (where `ecosystem IS NULL`).

### In-Memory Index Architecture

Two index structures behind `ArcSwap` for lock-free concurrent reads:

**`AdvisoryIndex`** — loaded at startup, updated incrementally on advisory ingest/delete:
- `by_base_purl: HashMap<Uuid, Vec<AdvisoryAssertion>>` — keyed by `base_purl_id`
- `by_cpe_identity: HashMap<(Arc<str>, Arc<str>), Vec<AdvisoryAssertion>>` — keyed by
  (vendor, product)
- `by_digest: HashMap<(Arc<str>, Arc<str>), Vec<AdvisoryAssertion>>` — keyed by
  (algorithm, hash_value)

**`SbomIndex`** — built per-SBOM, cached via `moka` (bounded LRU, configurable size):
- `packages_by_base_purl: HashMap<Uuid, Vec<SbomPackageEntry>>`
- `packages_by_cpe: HashMap<(Arc<str>, Arc<str>), Vec<SbomPackageEntry>>`
- `packages_by_digest: HashMap<(Arc<str>, Arc<str>), Vec<SbomPackageEntry>>`

`AdvisoryAssertion` carries the matcher criteria as a discriminated enum:

```rust
enum MatchCriteria {
    Purl {
        purl_type: Arc<str>,
        version_range: VersionRange,
        version_scheme: VersionScheme,
    },
    CpeIdentity {
        version_range: VersionRange,
        version_scheme: VersionScheme,
    },
    Digest,
}
```

Version comparators are ported to Rust (from the PL/pgSQL functions) and support:
semver (npm, cargo, golang, gem, nuget, etc.), RPM (with epoch), Maven,
Python (PEP 440), and generic (exact string equality).

### API Surface

New endpoints under `/api/v4/correlation/`:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sbom/{id}` | Materialized matches for an SBOM |
| GET | `/sbom/{id}/summary` | Severity counts from materialized data |
| POST | `/analyze` | Analyze PURLs against materialized + real-time |
| GET | `/vulnerability/{id}` | All SBOMs affected by a vulnerability |
| GET | `/vulnerability/{id}/summary` | Affected-SBOM count and severity breakdown |
| GET | `/match/{id}/evidence` | Evidence for a specific match |
| GET | `/state` | Correlation state across all entities (filterable by status) |
| GET | `/status` | Engine status (last run, index sizes, backlog) |
| POST | `/trigger` | Manual correlation trigger |
| GET | `/policy` | Current policy |
| PUT | `/policy` | Update policy |

Existing v3 endpoints remain unchanged. A later phase adds a feature-flagged adapter
that makes v3 endpoints read from `correlation_match` instead of computing at query time.

### Configuration

CLI args on the server's `Run` struct, mirroring the `correlation_policy` table:

| Flag | Env | Default |
|------|-----|---------|
| `--correlation-enabled` | `TRUSTD_CORRELATION_ENABLED` | true |
| `--correlation-purl-type-strict` | `TRUSTD_CORRELATION_PURL_TYPE_STRICT` | true |
| `--correlation-not-affected-suppresses` | `TRUSTD_CORRELATION_NOT_AFFECTED_SUPPRESSES` | true |
| `--correlation-digest-matching` | `TRUSTD_CORRELATION_DIGEST_MATCHING` | true |
| `--correlation-sbom-cache-size` | `TRUSTD_CORRELATION_SBOM_CACHE_SIZE` | 500 |

### Module Structure

```
modules/correlation/
  Cargo.toml
  src/
    lib.rs
    config.rs
    error.rs
    engine/
      mod.rs            -- CorrelationEngine
      index.rs          -- AdvisoryIndex, SbomIndex
      matcher/
        mod.rs          -- MatchPipeline, RawMatch
        purl.rs         -- PurlMatcher
        cpe.rs          -- CpeMatcher
        digest.rs       -- DigestMatcher
      version/
        mod.rs          -- VersionComparator trait
        semver.rs
        rpm.rs
        maven.rs
        python.rs
        generic.rs
      resolver.rs       -- StatusResolver
    service/
      mod.rs            -- CorrelationService
      state.rs            -- correlation_state queue management
      persist.rs
      hydrate.rs
      worker.rs
    model/
      mod.rs
      evidence.rs
    endpoints/
      mod.rs
      query.rs
      test.rs
```

### Server Integration

- `CorrelationConfig` added to `Run` struct in `server/src/profile/api.rs`
- `CorrelationEngine` constructed in `InitData::new()`, stored on `InitData`
- Background worker(s) spawned in `InitData::run()` (same pattern as EI worker)
- Workers poll `correlation_inbox` — no dependency on `ChangeBroadcaster`
- Endpoints registered in `configure()` under `/api` scope

### Phased Delivery

| Phase | Scope | Key deliverables |
|-------|-------|-----------------|
| 1 | Foundation | Crate skeleton, migration (4 tables + enums), entity models, Rust version comparators with unit tests |
| 2 | Engine | AdvisoryIndex, SbomIndex, PurlMatcher, CpeMatcher, DigestMatcher, StatusResolver, scenario tests passing |
| 3 | Persistence | correlation_state work queue, multi-worker with FOR UPDATE SKIP LOCKED, persist/hydrate, evidence recording, ingestor integration |
| 4 | API | v4 endpoints, OpenAPI docs, policy/inbox management, server registration |
| 5 | Migration | Feature-flagged v3 adapter, benchmarks, deprecation of `sbom/model/raw_sql.rs` |

### Prerequisite Work (separate PRs)

- **Ingestor: extract CSAF hashes** — extend CSAF loader to store
  `product_identification_helper.hashes` (needed for digest matching)
- **OSV loader: non-CVE aliases** — create advisory_vulnerability rows for GHSA/RUSTSEC
  IDs, not only CVE aliases (TC-5731)

## Consequences

### Positive

- **Correctness**: eliminates the root causes of failing scenarios — 6 bugs removed by
  dropping flawed matching paths (product_status, describing CPE, dist-tag scoping),
  remaining bugs fixed with correct implementations (PURL type check, status resolution,
  unbounded ranges, epoch handling)
- **Performance**: in-memory matching replaces query-time SQL, with materialized results
  eliminating repeated computation
- **Transparency**: every match carries evidence explaining why it was made
- **Configurability**: policy knobs let users tune matching behavior without code changes
- **Progress tracking**: inbox pattern provides visibility into correlation backlog
- **Spec compliance**: matching follows CSAF v2.0 / VEX consumer guidance

### Trade-offs

- **Additional storage**: materialized results and evidence consume disk space proportional
  to (SBOMs x advisories x matches). Most matches produce 1–3 evidence rows.
- **Eventual consistency**: correlation results may lag behind ingestion by the time it
  takes the worker to process the inbox. The inbox endpoint provides visibility into this.
- **Memory usage**: the AdvisoryIndex is held in memory. For the DS3 dataset this is
  manageable; for very large deployments the index may need partitioning or tiering.
- **Migration effort**: existing v3 consumers continue working unchanged during the
  transition period, but full cutover requires testing the v3 adapter.

### Known Limitations and Future Work

- **Containers and layered products**: non-RPM content in container images (Go
  modules, Maven artifacts) requires agreed PURL namespace conventions that are
  not always standardized. The engine matches whatever PURLs are present in the
  SBOM and advisory; namespace normalization or convention enforcement is out of
  scope.
- **Static linking and vendored dependencies**: a single vendored-module
  vulnerability fans out across every binary that embedded it (e.g., Go stdlib).
  The engine produces a match per SBOM node; deduplication or rollup across
  binaries is a presentation/UI concern, not a matching concern.
- **Name mismatch between vendors and NVD**: package names used by vendors (e.g.,
  Red Hat) may differ from the names NVD publishes for the same component. This
  can cause false negatives when the PURL or CPE names don't align. A future
  aliasing/mapping table could bridge this gap.
- **Source-to-binary PURL gap**: see the note under PURL matching above. A
  relationship-based dimension (SPDX `GENERATED_FROM`, build metadata) is needed
  to bridge source and binary package identities.
- **SBOM trust signals**: digest matching confidence assumes the SBOM is
  trustworthy. Signed SBOMs should carry higher weight than unsigned ones. The
  policy model is designed to accommodate a future trust-level field.

### What This Does NOT Change

- **Ingestion pipeline**: SBOMs and advisories are still ingested by the existing ingestor
  module. The `purl_status`, `product_status`, and `cpe_status` tables continue to be
  populated at ingestion time — the correlation engine reads from them.
- **Change notification infrastructure**: the `ChangeBroadcaster`, `ChangeListener`, and
  `change_log` table remain unchanged. They continue to serve the notification module and
  any other consumers. The correlation module does not subscribe to them — it uses its
  own `correlation_state` table as a work queue instead.
- **Analysis module**: the graph-walking analysis service is orthogonal and unaffected.
- **v3 API contract**: response shapes for v3 endpoints remain identical.

## References

- [Correlation Test Suite Evaluation (gist)](https://gist.github.com/ctron/6bfcb575068f52a2fb90a5ab0c1176b9)
- [PR #2528: In-memory correlation engine prototype](https://github.com/guacsec/trustify/pull/2528)
- [PR #2540: ADR describing current correlation state](https://github.com/guacsec/trustify/pull/2540)
- [CSAF v2.0 specification — product_identification_helper](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
- Test scenarios: `etc/test-data/scenarios/S1-S18/`
