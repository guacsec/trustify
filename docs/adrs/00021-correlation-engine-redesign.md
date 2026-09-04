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

### Performance

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

**CPE identity matching (confidence: 0.8)** — for CVE/NVD data and CSAF advisories
that identify components by CPE. Matches by vendor+product (part='a') with version
comparison using `COALESCE(cpe_version, package_version)` for the SBOM side.

**Digest matching (confidence: 1.0)** — the strongest possible match per spec.
Exact hash-value lookup with no version comparison needed. Requires ingestor extension
to extract `product_identification_helper.hashes` from CSAF documents (prerequisite work).

### Status Resolution

All VEX statuses are honored, not just `affected`. When multiple assertions exist for the
same `(sbom_node, vulnerability)`:

1. `not_affected` from any advisory suppresses `affected` (configurable)
2. `fixed` suppresses `affected` (configurable)
3. `under_investigation` surfaces as-is
4. `affected` is the default when no suppression applies

### Inbox Queue Pattern

On document ingestion, a change event (via the existing `ChangeBroadcaster`) enqueues
an entry in `correlation_inbox` with status `pending`. A background worker:

1. Picks up `pending` entries, marks them `processing`
2. Builds or updates the in-memory index for the entity
3. Runs the matching pipeline
4. Persists results to `correlation_match` and `correlation_evidence`
5. Marks the inbox entry `completed` (or `failed` with error)

This decouples ingestion from correlation, provides progress visibility, enables retry
on failure, and supports backpressure during bulk ingestion.

### Database Schema

All fixed value sets use PostgreSQL ENUMs with `DeriveActiveEnum`:

```sql
CREATE TYPE correlation_entity_type AS ENUM ('sbom', 'advisory');
CREATE TYPE correlation_inbox_status AS ENUM ('pending', 'processing', 'completed', 'failed');
CREATE TYPE correlation_run_status AS ENUM ('running', 'completed', 'failed');
CREATE TYPE correlation_trigger AS ENUM ('sbom_ingested', 'advisory_ingested', 'full_rebuild', 'manual');
CREATE TYPE correlation_status AS ENUM ('affected', 'not_affected', 'fixed', 'under_investigation');
CREATE TYPE match_dimension AS ENUM ('purl', 'cpe_identity', 'digest');
CREATE TYPE evidence_source AS ENUM ('purl_status', 'cpe_status');
```

**`correlation_inbox`** — documents awaiting correlation:

| Column | Type | Notes |
|--------|------|-------|
| id | UUID (v7) PK | |
| entity_type | correlation_entity_type | |
| entity_id | UUID | sbom_id or advisory.id |
| status | correlation_inbox_status | pending → processing → completed/failed |
| error_message | TEXT | nullable |
| created_at | TIMESTAMPTZ | |
| started_at | TIMESTAMPTZ | nullable |
| completed_at | TIMESTAMPTZ | nullable |

**`correlation_run`** — tracks each correlation execution:

| Column | Type | Notes |
|--------|------|-------|
| id | UUID (v7) PK | |
| inbox_id | UUID FK → correlation_inbox | nullable (null for full rebuilds) |
| started_at | TIMESTAMPTZ | |
| completed_at | TIMESTAMPTZ | nullable |
| trigger_type | correlation_trigger | |
| trigger_entity_id | UUID | nullable |
| matches_created | INT | |
| matches_removed | INT | |
| status | correlation_run_status | |

**`correlation_match`** — materialized result per (node, vuln, advisory):

| Column | Type | Notes |
|--------|------|-------|
| id | UUID (v7) PK | |
| correlation_run_id | UUID FK → correlation_run | CASCADE |
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
| purl_type_strict | BOOLEAN | true | require PURL type match |
| not_affected_suppresses | BOOLEAN | true | not_affected beats affected |
| fixed_suppresses | BOOLEAN | true | fixed beats affected |
| digest_matching | BOOLEAN | true | enable hash-based matching |

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
| GET | `/match/{id}/evidence` | Evidence for a specific match |
| GET | `/inbox` | Inbox queue status |
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
      inbox.rs
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
- Background worker spawned in `InitData::run()` (same pattern as EI worker)
- Worker subscribes to existing `ChangeBroadcaster` (already in `InitData`)
- Endpoints registered in `configure()` under `/api` scope

### Phased Delivery

| Phase | Scope | Key deliverables |
|-------|-------|-----------------|
| 1 | Foundation | Crate skeleton, migration (5 tables + enums), entity models, Rust version comparators with unit tests |
| 2 | Engine | AdvisoryIndex, SbomIndex, PurlMatcher, CpeMatcher, DigestMatcher, StatusResolver, scenario tests passing |
| 3 | Persistence | Inbox service, background worker, ChangeBroadcaster subscription, persist/hydrate, evidence recording |
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

### What This Does NOT Change

- **Ingestion pipeline**: SBOMs and advisories are still ingested by the existing ingestor
  module. The `purl_status`, `product_status`, and `cpe_status` tables continue to be
  populated at ingestion time — the correlation engine reads from them.
- **Analysis module**: the graph-walking analysis service is orthogonal and unaffected.
- **v3 API contract**: response shapes for v3 endpoints remain identical.

## References

- [Correlation Test Suite Evaluation (gist)](https://gist.github.com/ctron/6bfcb575068f52a2fb90a5ab0c1176b9)
- [PR #2528: In-memory correlation engine prototype](https://github.com/guacsec/trustify/pull/2528)
- [PR #2540: ADR describing current correlation state](https://github.com/guacsec/trustify/pull/2540)
- [CSAF v2.0 specification — product_identification_helper](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
- Test scenarios: `etc/test-data/scenarios/S1-S18/`
