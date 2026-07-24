# 00021. Vulnerability Correlation Engine Refactor

Date: 2026-07-24

## Status

DRAFT

## Context

[ADR 00020](00020-vulnerability-correlation-engine.md) documents the status quo of the
vulnerability correlation engine: six independent SQL queries (A1–A3 for Direction A,
B1–B3 for Direction B) that are not guaranteed to agree, have different scoping semantics,
and suffer from performance problems on large datasets.

[PR #2528](https://github.com/guacsec/trustify/pull/2528) attempted to fix this by building
a parallel in-memory correlation module (`modules/correlation/`) with its own advisory and
SBOM indexes loaded into `HashMap`s at startup. While it achieved 4–24x speedups, it had
fundamental problems:

- **Startup penalty**: loading all advisory and SBOM indexes into memory takes minutes on
  large datasets (270k SBOMs), making the server unusable during warmup.
- **Duplicate data model**: built its own `AdvisoryIndex` and `SbomIndex` rather than
  reusing the existing graph cache (`modules/analysis/`), which already stores
  `PackageNode` data (PURLs, CPEs, versions) per SBOM in a bounded moka cache.
- **Scope creep**: bundled WebSocket notifications, change_log tables, and a
  `ChangeBroadcaster` into the same PR.
- **Incomplete coverage**: `correlate_purls` only queried `purl_status` initially; CPE
  matching (`cpe_status`) was absent entirely.

This ADR proposes a refactor that reuses the existing graph cache infrastructure and
addresses the directional asymmetries documented in ADR 00020, without building a parallel
data model.

## Decision

### Principle: one matching layer, two entry points

Instead of six independent queries, implement a single `CorrelationService` that expresses
identity matching, version matching, and context scoping once. Direction A and Direction B
become two entry points into the same matching logic, parameterized by anchor side.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  CorrelationService                     │
│                                                         │
│  ┌─────────────────┐     ┌──────────────────────────┐  │
│  │  AdvisoryIndex   │     │  Graph Cache (existing)  │  │
│  │  (in-memory)     │     │  modules/analysis/       │  │
│  │                  │     │  PackageGraph per SBOM   │  │
│  │  by_purl:        │     │  - PackageNode.purl      │  │
│  │    HashMap<      │     │  - PackageNode.cpe       │  │
│  │      BasePurlKey,│     │  - PackageNode.version   │  │
│  │      Vec<Status>>│     │  moka LRU, 200 MiB      │  │
│  │  by_cpe:         │     │  eager load after ingest │  │
│  │    HashMap<      │     └──────────────────────────┘  │
│  │      CpeKey,     │                                   │
│  │      Vec<Status>>│                                   │
│  │  by_product_name:│                                   │
│  │    HashMap<      │                                   │
│  │      String,     │                                   │
│  │      Vec<Status>>│                                   │
│  └─────────────────┘                                    │
│                                                         │
│  correlate_sbom(sbom_id) → Vec<CorrelationMatch>        │
│  correlate_vuln(vuln_id) → Vec<CorrelationMatch>        │
│  correlate_purls(purls)  → Vec<CorrelationMatch>        │
└─────────────────────────────────────────────────────────┘
          │                          │
          ▼                          ▼
┌──────────────────┐    ┌─────────────────────────┐
│  Hydration Layer │    │  Existing Endpoints      │
│  (DB lookups)    │    │  GET /v3/sbom/{id}/adv   │
│  advisory, vuln, │    │  GET /v3/vulnerability/  │
│  scores, orgs    │    │      {id}                │
└──────────────────┘    └─────────────────────────┘
```

### Component 1: AdvisoryIndex (new, in-memory)

A read-optimized index over the advisory side of the correlation pivot. Loaded at startup
from `purl_status`, `cpe_status`, and `product_status` tables. Incrementally updated on
advisory ingest/delete via `change_log` events or direct notification.

```rust
struct AdvisoryIndex {
    /// PURL identity → status entries (with version ranges).
    /// Key: (purl_type, namespace, name) — same as base_purl identity.
    by_purl: HashMap<BasePurlKey, Vec<PurlStatusEntry>>,

    /// CPE identity → status entries (with version ranges).
    /// Key: (vendor, product) where part = 'a'.
    by_cpe: HashMap<CpeKey, Vec<CpeStatusEntry>>,

    /// Product name → status entries (with version ranges).
    /// Key: package name (both bare and namespace/name forms).
    by_product_name: HashMap<String, Vec<ProductStatusEntry>>,
}
```

Each `*StatusEntry` contains: `advisory_id`, `vulnerability_id`, `status_id`,
`version_range`, `context_cpe_id`, and the version scheme. This is the advisory's
*assertion* — it does not know about SBOMs.

**Why a separate index instead of querying the DB?** The advisory side is the smaller,
more stable half of the correlation. Status tables are write-once (at ingest time) and
change only when advisories are ingested or deleted. Keeping them in memory eliminates
the multi-join SQL queries that are the primary bottleneck. On the DS3 dataset, this
index is ~50–100 MB — well within server memory budgets.

**Why not reuse the graph cache for advisories?** The graph cache stores *SBOM dependency
trees* as petgraphs. Advisories are not graphs — they are flat assertion sets. Forcing
them into the graph model would be a poor fit. The advisory index is a simple HashMap
lookup structure.

### Component 2: reuse the existing graph cache for SBOM data

PR #2528's `SbomIndex` duplicated what the existing `GraphMap` already stores. Each
`PackageNode` in the graph cache already contains:

- `purl: Arc<[Purl]>` — all qualified PURLs for the package
- `cpe: Arc<[Cpe]>` — all CPEs for the package
- `version: String` — the package version
- `name: String` — the package name
- `sbom_id: Uuid` — which SBOM this belongs to

For Direction A (`correlate_sbom`), the flow is:

1. Load the SBOM's `PackageGraph` from the graph cache (cache hit or DB load).
2. Iterate over all `PackageNode`s in the graph.
3. For each node, look up its PURLs in `AdvisoryIndex.by_purl`, its CPEs in
   `AdvisoryIndex.by_cpe`, and its name in `AdvisoryIndex.by_product_name`.
4. For each matching status entry, run `version_matches()` in Rust (not PL/pgSQL).
5. Apply context CPE scoping using the SBOM's describing CPEs (from the graph's
   root/DESCRIBES node).
6. Collect and deduplicate matches.

For Direction B (`correlate_vuln`), the flow is:

1. Query `AdvisoryIndex` for all status entries mentioning the given `vulnerability_id`.
   This requires a secondary index: `by_vuln: HashMap<String, Vec<StatusEntryRef>>`.
2. For each status entry, determine which SBOMs could match:
   - For PURL entries: query DB for SBOMs containing a matching `base_purl` (this is
     a simple indexed lookup, not the full multi-join).
   - For CPE entries: query DB for SBOMs with matching `sbom_node_cpe_ref`.
   - For product name entries: query DB for SBOMs with matching package names.
3. For each candidate SBOM, load its graph from the cache and verify the version match
   and context scoping (same logic as Direction A step 4–5).
4. Collect and deduplicate.

This ensures both directions execute the **same matching logic** — eliminating the
directional asymmetries documented in ADR 00020 (L11–L15).

### Component 3: Rust version matching (port from PL/pgSQL)

PR #2528 already ported the version comparison functions to Rust. This work should be
extracted and reused:

- `semver_version_matches` — covers npm, NuGet, Cargo, Gem, Hex, Swift, Pub, Packagist
- `rpm_version_matches` — RPM epoch:version-release
- `maven_version_matches` — Maven ordering
- `python_version_matches` — PEP 440
- `golang_version_matches` — Go module versioning
- `generic_version_matches` — exact string equality

These replace the `version_matches()` PL/pgSQL function for the in-memory path. The SQL
function remains for direct DB queries outside the correlation engine.

### Component 4: context CPE scoping (unified)

Both directions currently apply context CPE scoping differently (or not at all — see
L5, L13, L14 in ADR 00020). The refactored engine applies a single scoping rule:

1. Extract the SBOM's describing CPEs from its graph (the root node's CPEs, or
   `sbom_describing_cpe` as fallback).
2. Generalize to `(vendor, product, major_version)` triples.
3. A status entry matches if:
   - Its `context_cpe_id` is NULL (universal), OR
   - Its context CPE matches one of the generalized describing CPEs, OR
   - The SBOM has no describing CPEs (unscoped SBOMs match everything).

This is Direction A's current rule (which is the more correct one), applied uniformly
to both directions and all three matching strategies.

### Component 5: hydration layer

The correlation engine produces `Vec<CorrelationMatch>` — lightweight structs containing
only IDs (`advisory_id`, `vulnerability_id`, `status_id`, `sbom_id`, `purl_id`, etc.).
A hydration layer performs batched DB lookups to inflate these into the full API response
models (`SbomAdvisory`, `VulnerabilityDetails`, etc.).

This is the same approach PR #2528 took, and it is sound: the hot path (identity matching +
version comparison) runs in memory, and the cold path (entity metadata) is a small number
of batched `WHERE id IN (...)` queries.

### Component 6: status filter unification (F10)

Both directions use the same status filter, configurable per request:

- Direction A default: `["affected"]` (current behavior, backward compatible)
- Direction B default: `["affected", "fixed", "under_investigation", "recommended"]`
  (current `!= 'not_affected'` behavior, made explicit)

The caller can override with a `status` query parameter on both endpoints.

### Incremental update strategy

The `AdvisoryIndex` is rebuilt on advisory ingest/delete. Two options:

**Option A — full rebuild on change.** The advisory index is small enough (~50–100 MB)
that a full rebuild from DB takes 2–5 seconds. Use `ArcSwap` for lock-free reads during
rebuild. Triggered by `change_log` events or a periodic poll.

**Option B — incremental delta.** On advisory ingest, query only the new/changed
`purl_status`/`cpe_status`/`product_status` rows and merge them into the index. On
advisory delete, remove entries by `advisory_id`. More complex but avoids the rebuild
pause.

Recommend starting with **Option A** for simplicity, with Option B as an optimization
if the rebuild pause proves problematic.

### What this does NOT change

- **Ingestion paths** — loaders, creators, status tables, version scheme assignment.
  These are separate concerns (L1, L2, L3, L8, L9, L10 in ADR 00020).
- **The analysis module** — graph cache, cross-SBOM traversal, `/v3/analysis/` endpoints.
  The correlation service *consumes* the graph cache but does not modify it.
- **Database schema** — no new tables or migrations. The `purl_status`, `cpe_status`,
  `product_status`, and `version_range` tables remain the source of truth.

### Limitations addressed

| ADR 00020 ID | Status | How |
|---|---|---|
| L5 | Fixed | Context CPE scoping applied uniformly to all matching strategies |
| L11 | Fixed | Single status filter definition, configurable per request |
| L12 | Fixed | Product name matching uses `=` in both directions (no `LIKE`) |
| L13 | Fixed | Context CPE scoping applied to PURL matches in Direction B |
| L14 | Fixed | Single scoping mechanism for product name matches |
| L15 | Enabled | Cross-direction consistency tests become trivial (same code path) |
| L16 | Fixed | DESCRIBES spine used for projection only, not filtering |
| L7, L19 | Fixed | N+1 queries eliminated by batched hydration |

### Limitations NOT addressed (out of scope)

| ADR 00020 ID | Why |
|---|---|
| L1 | CVE PURL divination — ingestion concern |
| L2 | Generic version scheme — ingestion concern (L10 is the root cause) |
| L3 | Product name normalization — ingestion concern |
| L4 | Context CPE major-version-only — deliberate design choice, revisit separately |
| L6 | Cross-advisory dedup — separate feature (F8) |
| L8 | Red Hat CSAF heuristic — ingestion concern |
| L10 | Version scheme assignment — ingestion concern (F9) |
| L17 | CPE-only nodes — data model artifact, requires entity changes |
| L18 | Legacy `purls` field — API deprecation decision (F15) |
| L20 | Non-deterministic version — fixed as side effect (graph iteration is stable) |

## Migration plan

### Phase 1: extract and test the matching layer

1. Port version comparison functions from PR #2528 into `common/src/version/`.
2. Build `AdvisoryIndex` with `by_purl`, `by_cpe`, `by_product_name` indexes.
3. Implement `correlate_sbom()` — Direction A only.
4. Add correctness tests comparing in-memory results against SQL baseline.
5. Wire up behind a feature flag (`--correlation-enabled`).

### Phase 2: Direction B and hydration

1. Add `by_vuln` secondary index to `AdvisoryIndex`.
2. Implement `correlate_vuln()` — Direction B.
3. Build hydration layer for `VulnerabilityDetails` response format.
4. Add cross-direction consistency tests (F12 from ADR 00020).

### Phase 3: replace the SQL paths

1. Make the correlation service the default for `/v3/sbom/{id}/advisory` and
   `/v3/vulnerability/{id}`.
2. Keep the SQL paths available under `/v3a/` for comparison during validation.
3. Remove the SQL paths once correctness is confirmed at scale.

### Phase 4: cleanup

1. Remove `raw_sql.rs` query functions (`product_advisory_info_sql`,
   `cpe_advisory_info_sql`, `batch_severity_counts_sql`).
2. Remove the A1 SeaORM query chain in `details.rs`.
3. Remove B1/B2/B3 queries in `vulnerability_advisory.rs`.
4. Remove the legacy `purls` field (F15) or keep it explicitly documented.

## Consequences

- **Performance**: in-memory matching eliminates the multi-join SQL queries. PR #2528
  demonstrated 4–24x speedups; this design should achieve similar results without the
  startup penalty (the graph cache warms lazily).
- **Correctness**: a single matching layer guarantees directional consistency.
  The asymmetries documented in ADR 00020 (L11–L15) are eliminated by construction.
- **Memory**: the `AdvisoryIndex` adds ~50–100 MB of resident memory (advisory status
  entries). The existing graph cache (200 MiB default) is reused, not duplicated.
- **Startup**: unlike PR #2528, no upfront SBOM loading. The advisory index loads in
  2–5 seconds. SBOM graphs are loaded on demand via the existing graph cache.
- **Complexity**: replaces six SQL query implementations with one Rust matching
  function. The hydration layer adds new code, but it is straightforward batched
  DB lookups.
- **Risk**: version matching in Rust must produce identical results to the PL/pgSQL
  functions. Correctness tests against the SQL baseline mitigate this.

## References

- [ADR 00020](00020-vulnerability-correlation-engine.md) — status quo documentation
- [ADR 00001](00001-graph-analytics.md) — graph analytics design (petgraph + moka cache)
- [ADR 00002](00002-analysis-graph.md) — analysis graph model
- [PR #2528](https://github.com/guacsec/trustify/pull/2528) — prior in-memory
  correlation attempt (draft, not merged)
- `modules/analysis/src/model.rs` — `GraphMap`, `PackageGraph`, `PackageNode`
- `modules/analysis/src/service/mod.rs` — `AnalysisService`, graph cache loading
- `modules/fundamental/src/sbom/model/details.rs` — current Direction A queries
- `modules/fundamental/src/vulnerability/model/details/vulnerability_advisory.rs` —
  current Direction B queries
