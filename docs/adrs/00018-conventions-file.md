# 00018. Conventions File and Performance Anti-Pattern Standards

Date: 2026-05-14

## Status

ACCEPTED

## Context

Trustify needs a single, explicit reference for coding patterns, naming rules, error-handling idioms, testing practices, and architectural norms. Contributors and reviewers use it during implementation and review; the same clarity also helps AI-assisted workflows (Claude Code, Copilot, and similar tools) when those tools load project context.

### Current Situation

Today, project conventions are scattered across tribal knowledge among maintainers,
code-review feedback, and implicit patterns in existing code. This leads to:
- **Inconsistent contributions**: new code diverges from established patterns (e.g., different error handling in different modules)
- **Repeated review feedback**: maintainers correct the same convention violations across PRs
- **AI hallucination**: AI tools infer conventions from files they happen to read which leads to adopting anti-patterns from older code
- **Onboarding friction**: new contributors don't have a quick reference

### What a Conventions File Provides

A `CONVENTIONS.md` file at the repository root serves as a reference for project-wide coding conventions. It:
- Lives next to the code it governs, evolving with the project
- Is automatically loaded by AI tools (Claude Code reads `CONVENTIONS.md` as context)
- Provides a reviewable, diff-able record of convention decisions
- Serves both as a contributor guide and an AI prompt artifact

## Decision

Review and update the `CONVENTIONS.md` file at the repository root that documents the project's coding conventions, patterns, and practices. The file is maintained as living documentation — updated through the normal PR process as conventions evolve.

### Scope

The conventions file covers:

| Section | Purpose | Examples |
|---------|---------|---------|
| **Language and Framework** | Technology stack and core dependencies | Rust edition, Actix-web, SeaORM, Tokio |
| **Code Style** | Formatting and lint rules | `rustfmt` defaults, clippy flags, `unwrap()` policy |
| **Naming Conventions** | Naming patterns for all code elements | Structs, functions, modules, endpoints, OpenAPI IDs |
| **File Organization** | Workspace layout and module structure | Domain module pattern (endpoints/service/model) |
| **Error Handling** | Error type design and propagation | `thiserror` enums, `ResponseError` mapping, `From<DbErr>` |
| **Testing Conventions** | Test infrastructure and patterns | `TrustifyContext`, test placement, assertion style |
| **Commit Messages** | Commit format and trailers | Conventional Commits, Jira references |
| **Pre-commit Workflow** | CI-equivalent local checks | `cargo xtask precommit` steps |
| **Dependencies** | Dependency management policy | Workspace-level pinning, key crate choices |
| **Endpoint Patterns** | HTTP endpoint conventions | `configure()`, authorization, transactions, OpenAPI |
| **Entity Model Patterns** | ORM model conventions | `DeriveEntityModel`, relations, `Linked` structs |
| **Migration Patterns** | Database migration conventions | Idempotency guards, naming, raw SQL loading |
| **Rust Idioms** | Preferred Rust patterns | Type inference, iterator ownership, `.zip()`, capacity |
| **SeaORM Query Patterns** | ORM query conventions | `.is_in()`, chunking |
| **Observability** | Tracing and instrumentation | `#[instrument]` usage, span conventions, error levels |

### Content Principles

1. **Prescriptive, not descriptive**: each convention states what to do and what to avoid, with concrete code examples
2. **Derived from existing code**: conventions are extracted from established patterns in the codebase, not invented
3. **Minimal and actionable**: each entry should be short enough that a contributor (or AI tool) can apply it without reading surrounding prose
4. **Reference implementations**: share canonical examples
5. **No duplication with tooling**: don't restate what `rustfmt` or `clippy` already enforce — reference their configuration instead

### Maintenance Process

- **Updates via PR**: convention changes follow the same review process as code changes
- **ADR linkage**: significant convention changes that reflect architectural decisions should reference the relevant ADR
- **Deprecation**: when a convention is superseded, update the section rather than appending contradictory guidance
- **Scope creep guard**: the file documents *conventions* (how to write code), not *architecture* (why the system is designed this way) — architecture belongs in ADRs

### AI Tool Integration

The conventions file is designed to be consumed by AI coding assistants:
- Claude Code automatically loads `CONVENTIONS.md` from the repository root as part of its project context
- The file uses markdown with code blocks, making it parseable by any LLM
- Conventions are structured as clear rules with examples, optimizing for AI instruction-following
- When a `CLAUDE.md` file is present (for tool-specific configuration), `CONVENTIONS.md` complements it — `CONVENTIONS.md` focuses on language and framework patterns that apply regardless of the tool

## Consequences

### Positive

- **Better AI output**: AI tools generate code that matches project style from the first attempt
- **Onboarding**: new contributors can read one file to understand "how we write code here"
- **Consistency**: single source of truth reduces convention drift across modules and contributors
- **Faster reviews**: reviewers can reference specific convention sections instead of explaining patterns from scratch
- **Accountability**: convention changes are tracked in git history with review

### Trade-offs

- **Living document**: conventions are not set in stone — they evolve through the ADR and PR process to improve how we work. When a convention changes, existing code is refactored to align. The goal is continuous improvement, not rigid enforcement
- **Completeness tension**: too few conventions and the file is unhelpful; too many and it becomes noise that contributors (and AI tools) ignore
- **Convention vs. enforcement gap**: not all conventions can be enforced by CI — some rely on review discipline

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| File becomes outdated | Treat convention violations in review as a signal to update the file |
| File grows too large for contributors and AI context windows | Keep entries concise; split into linked files if needed |
| Conventions conflict with each other | PR review process catches contradictions before merge |
| Over-prescription stifles judgment calls | Focus on patterns with clear consensus; leave room for discretion |

## Anti-Pattern Analysis

Analysis of the Trustify codebase has identified recurring anti-patterns across
multiple modules. This section catalogs each category, lists the occurrences found, and
presents convention options for the team to evaluate. The selected conventions will be
codified in `CONVENTIONS.md` and enforced through code review and AI-assisted development
workflows.

Each category below follows this structure:
- **What it is** — description of the anti-pattern
- **Why it matters** — performance impact, maintainability, consistency
- **Occurrences found** — Function/symbol name
- **Convention options** — choices for the team to decide on (to be resolved via PR review)

> **How to use this section**: During PR review, maintainers should mark their preferred
> option for each category. Once consensus is reached, the selected conventions will be
> added to `CONVENTIONS.md` and this ADR's status will change from PROPOSED to ACCEPTED.

---

### AP-1: N+1 Query Anti-pattern

**What it is**: Database queries executed inside loops — fetching related data one entity
at a time instead of loading all related data in a single batch query.

**Why it matters**: For a list of N entities, this generates N additional queries instead of
1 batch query. On API read paths serving collections, this scales linearly with result size
and dominates response latency.

**Occurrences found (5)**:

| # | File | Line(s) | Description | Severity |
|---|------|---------|-------------|----------|
| 1 | `modules/fundamental/src/advisory/model/summary.rs` | ~46 | Per-advisory vulnerability query inside `for each in entities` loop | High |
| 2 | `modules/fundamental/src/purl/model/summary/type.rs` | ~36 | Per type name: 3 sequential SQL `COUNT` aggregate queries in a loop (latency / many round-trips), not row-level N+1; could be consolidated (e.g. `COUNT` … `GROUP BY type`) | Medium |
| 3 | `modules/fundamental/src/license/service/mod.rs` | ~106 | 2 queries per package-license entry (PURLs + CPEs) in a loop | Medium |
| 4 | `modules/fundamental/src/purl/model/details/purl.rs` | ~279 | Up to 3 DB queries per iteration via `PurlStatus::from_entity` (status, CPE, version_range lookups by ID), plus additional queries from `PurlStatus::new` (`VulnerabilityHead` description, `AdvisoryHead`); conditional organization query in the parent loop | High |
| 5 | `modules/fundamental/src/purl/model/details/versioned_purl.rs` | ~134-145 | `VersionedPurlStatus::from_entity()` per iteration calls `VulnerabilityHead::from_vulnerability_entity(..., Memo::NotProvided, tx)`, which issues a per-iteration `SELECT` for `vulnerability_description` (lang = "en"). Bulk loading for other relations is already done outside the loop, but this read-side N+1 remains. | Medium |

> **Note**: Some loop-based queries (e.g., `purl/service/mod.rs` lines 575, 730, 755) are
> intentional chunking for PostgreSQL's 65535 bind-parameter limit. These are valid patterns
> and are not N+1 issues.

**Convention options**:

- **Option A — Batch with JOINs/IN clauses**: All collection data access MUST use batch
  loading (SQL JOINs, `.is_in()`, or SeaORM `load_one`/`load_many`). Per-entity DB calls
  inside loops are prohibited on all code paths. Existing N+1 patterns become tech debt
  to remediate.

  ```rust
  // Approved: batch load with JOIN or IN clause
  let vulns = advisory_vulnerability::Entity::find()
      .filter(advisory_vulnerability::Column::AdvisoryId.is_in(advisory_ids))
      .all(tx)
      .await?;

  // Approved: SeaORM batch loader
  let orgs = advisories.load_one(organization::Entity, tx).await?;
  ```

- **Option B — Batch for read paths only**: N+1 is prohibited on API read paths (GET
  endpoints). Allowed on write/delete paths where entity counts are typically small and
  transactional isolation may require per-entity operations.

- **Option C — Keep as-is**: No convention. Performance is addressed case-by-case when
  bottlenecks are observed. N+1 patterns are acceptable if the loop iteration count is
  expected to be small.

- **Option D — Prefer batch, allow exceptions**: Default to Option A — batch loading on
  collection paths and remediate existing N+1 patterns as tech debt. Per-entity DB calls
  inside loops are permitted only when batching is impractical or costly.

  **Preferred Option:** - Option D

  - **Prefer batch, allow exceptions**: Default to Option A — batch loading on
  collection paths and remediate existing N+1 patterns as tech debt. Per-entity DB calls
  inside loops are permitted only when batching is impractical or costly.

---

### AP-2: Unbounded Queries

**What it is**: Queries that fetch all rows from a table or relation without applying
`LIMIT`, pagination, or any bound on result size.

**Why it matters**: As data grows, unbounded queries consume increasing memory and network
bandwidth. A single unbounded query on a large table can cause OOM or timeout.

**Occurrences found (3)**:

| # | File | Line(s) | Description |
|---|------|---------|-------------|
| 1 | `modules/importer/src/service.rs` | ~133 | `importer::Entity::find().all()` fetches all importers, sorts in memory |
| 2 | `modules/fundamental/src/advisory/model/summary.rs` | ~47 | `.all(tx)` per advisory fetching all related vulnerabilities |
| 3 | `modules/fundamental/src/vulnerability/model/details/mod.rs` | ~46-57 | `.all(tx)` fetching all advisory-vulnerabilities and all scores **filtered by `vulnerability_id`** — not a full table scan, but lacks `LIMIT`; risk is unbounded per-entity fan-out if a single vulnerability has many advisories/scores |

**Convention options**:

- **Option A — Require pagination or limits on all queries**: All list/collection endpoints
  MUST use the `Paginated` wrapper. Internal service queries on potentially-large tables
  must use `.limit()` or chunked iteration. Exceptions only for tables with a known small
  upper bound (e.g., importers, which are admin-configured).

- **Option B — Limit only on public API endpoints**: Public API list endpoints must be
  paginated using `PaginatedResults`. Internal service queries may be unbounded if the
  caller controls scope and the table is known to be bounded in practice.

- **Option C — Keep as-is**: No convention. Rely on practical table sizes remaining small.
  Address unbounded queries only when they cause observed problems.

**Preferred Option:** - Option B

- **Limit only on public API endpoints**: Public API list endpoints must be
  paginated using `PaginatedResults`. Internal service queries may be unbounded if the
  caller controls scope and the table is known to be bounded in practice.
---

### AP-3: In-Memory Filtering Instead of SQL WHERE

**What it is**: Fetching a full dataset from the database and then filtering it in
application code (Rust iterators) instead of pushing the filter condition into the SQL
WHERE clause.

**Why it matters**: Transfers unnecessary data over the network, consumes application memory,
and bypasses database index optimizations. The performance gap widens as the unfiltered
dataset grows.

**Occurrences found (0)**:

No confirmed occurrences. The previously cited cases (`vulnerability/model/details/mod.rs`
and `advisory/model/summary.rs`) are false positives — both intentionally bulk-load data
and re-use it across multiple consumers to avoid N+1 queries. This category is included
as a preventive convention.

**Convention options**:

- **Option A — Push all filters to SQL**: Filtering MUST be expressed in SQL WHERE clauses.
  Post-fetch filtering in Rust is prohibited unless the filter logic cannot be expressed
  in SQL (e.g., values computed only in application code after graph resolution, complex
  business rules requiring deserialized JSON fields).

  ```rust
  // Approved: filter in SQL
  advisory_vulnerability_score::Entity::find()
      .filter(advisory_vulnerability_score::Column::AdvisoryId.eq(advisory_id))
      .all(tx)
      .await?;

  // Prohibited: fetch-then-filter
  let all_scores = advisory_vulnerability_score::Entity::find().all(tx).await?;
  let filtered: Vec<_> = all_scores.into_iter()
      .filter(|s| s.advisory_id == advisory_id)
      .collect();
  ```

- **Option B — Push to SQL for large datasets only**: Filter in SQL for tables/joins that
  can produce more than ~100 rows. Small known-bounded collections may filter in Rust
  for readability.

- **Option C — Keep as-is**: No convention. In-memory filtering is acceptable when the
  developer judges the dataset to be small.

**Preferred Option:** - Awaiting decision

---

### AP-4: Application-Side Counting

**What it is**: Using `.len()` (or equivalent) as a substitute for SQL `COUNT()` when rows
were loaded from the database **only** to obtain a count — materializing a large result
set that is not otherwise needed.

**Why it matters**: Transfers and deserializes every row just to count them. For paginated
endpoints, this means fetching the entire table to compute `total` instead of a single
aggregate query.

**Occurrences found (0)**:

No confirmed occurrences were found. The previously cited case
(`modules/analysis/src/model/roots.rs` — `items.len()` after `roots()` / `root_traces()`)
operates on an **already in-memory** graph-transformed collection, not on rows fetched
solely to obtain a count. It does not match this anti-pattern's definition. The pagination
`total` semantics there may still warrant review, but as a separate concern — not as
application-side counting. This category is included as a preventive convention to guard
against future introductions, not as remediation of existing debt.

**Convention options**:

- **Option A — Use SQL COUNT()**: Counts MUST be computed in the database using `COUNT()`,
  not by materializing rows and calling `.len()`. Exception: if the full collection is
  already materialized for another purpose in the same scope, `.len()` is acceptable to
  avoid a redundant query.

  ```rust
  // Approved: SQL count
  let total = entity::Entity::find()
      .filter(condition)
      .count(tx)
      .await?;

  // Prohibited (for count-only purposes):
  let items = entity::Entity::find().filter(condition).all(tx).await?;
  let total = items.len();
  ```

- **Option B — SQL COUNT for paginated endpoints only**: Paginated endpoints must use SQL
  `COUNT()` for the `total` field. Internal service code may use `.len()` if the full
  dataset is already loaded for processing.

- **Option C — Keep as-is**: No convention. `.len()` on query results is acceptable for
  simplicity.

- **Option D - Default to SQL COUNT; allow exceptions**: Follow Option A as the normal rule:
  ask the database for a count (`COUNT()`), do not load all rows just to call `.len()`.
  The only time `.len()` is fine is when you already loaded those rows for something else
  in the same function — counting them again with SQL would be a wasted query.

**Preferred Option:** - Option D

- **Default to SQL COUNT; allow exceptions**: Follow Option A as the normal rule:
  ask the database for a count (`COUNT()`), do not load all rows just to call `.len()`.
  The only time `.len()` is fine is when you already loaded those rows for something else
  in the same function — counting them again with SQL would be a wasted query.
---

### AP-5: Missing Batch/Bulk Operations

**What it is**: Individual insert, update, or delete operations executed one at a time
inside a loop instead of using bulk/batch equivalents.

**Why it matters**: Each individual operation incurs a network round-trip to the database.
Batch operations reduce this to a single round-trip for the entire collection.

**Occurrences found (0)**:

No confirmed occurrences of missing **bulk write** operations were found. The previously
cited case (`versioned_purl.rs` ~134-145) is a read-side N+1 pattern
(`VulnerabilityHead::from_vulnerability_entity` with `Memo::NotProvided` issuing a
per-iteration `SELECT` for `vulnerability_description`). It has been reclassified under
**AP-1: N+1 Query Anti-pattern** where it fits the definition. This category is included
as a preventive convention to guard against future introductions, not as remediation of
existing debt.

**Convention options**:

- **Option A — Use bulk operations**: Write operations (insert, update, delete) on
  collections MUST use bulk equivalents. Use `Entity::insert_many()` for batch inserts,
  `Entity::delete_many().filter(Column.is_in(ids))` for batch deletes. Individual
  operations in loops are prohibited unless transactional isolation requires it.

  ```rust
  // Approved: batch delete
  source_document::Entity::delete_many()
      .filter(source_document::Column::Id.is_in(doc_ids))
      .exec(tx)
      .await?;

  // Prohibited: individual deletes in loop
  for doc in &docs {
      source_document::Entity::delete_by_id(doc).exec(tx).await?;
  }
  ```

- **Option B — Bulk for large collections only**: Bulk operations are required when the
  collection size can exceed ~10 items. Small fixed-size loops (e.g., deleting 1-3 related
  entities) may use individual operations.

- **Option C — Keep as-is**: No convention. Individual operations in loops are acceptable
  for clarity. Batch operations are a performance optimization to apply when needed.

- **Option D - Bulk when many; single when one**: Use bulk operations (`insert_many`,
  `delete_many`, etc.) when deleting or inserting multiple entries in one operation. When
  the API or code path handles a single item only (e.g. `DELETE /resource/{id}`), a single
  `delete_by_id` (or equivalent) is acceptable — no need to batch.

**Preferred Option:** - Option D
- **Bulk when many; single when one**: Use bulk operations (`insert_many`,
  `delete_many`, etc.) when deleting or inserting multiple entries in one operation. When
  the API or code path handles a single item only (e.g. `DELETE /resource/{id}`), a single
  `delete_by_id` (or equivalent) is acceptable — no need to batch.
---

### AP-6: Recursive Graph Traversal Without Depth Limits

**What it is**: Recursive DFS traversal of graph-like structures (dependency trees,
product branch hierarchies) without any depth bound, risking stack overflow or unbounded
computation on deep/cyclic graphs.

**Why it matters**: Dependency trees in SBOMs can be deeply nested. Without depth limits,
a single malformed or deeply nested document can cause stack overflow or excessive
computation time.

**Occurrences found (2)**:

| # | File | Line(s) | Description |
|---|------|---------|-------------|
| 1 | `modules/analysis/src/model/roots.rs` | ~24-35, 68-88 | Two `roots_into` functions — recursive DFS with ancestor vector cloning per call |
| 2 | `modules/ingestor/src/service/advisory/csaf/util.rs` | ~50-64 | `walk_product_branches_ref` — recursive DFS with no depth limit |

**Convention options**:

- **Option A — Require depth limits and iterative traversal**: All graph/tree traversals
  MUST have a configurable maximum depth. Prefer iterative (stack-based) traversal over
  recursive functions to avoid stack overflow. Recursive implementations must include a
  depth counter parameter.

  ```rust
  // Approved: iterative with depth limit
  fn walk_ancestors(start: &Node, max_depth: usize) -> Vec<Node> {
      let mut stack = vec![(start, 0)];
      let mut result = Vec::new();
      while let Some((node, depth)) = stack.pop() {
          if depth >= max_depth { continue; }
          result.push(node.clone());
          for parent in &node.ancestors {
              stack.push((parent, depth + 1));
          }
      }
      result
  }
  ```

- **Option B — Depth limits only**: Recursive traversal is acceptable but MUST include a
  maximum depth parameter. No requirement to convert to iterative. Reasonable default
  depth: 256.

- **Option C — Keep as-is**: No convention. Trust that input data is well-formed. Address
  traversal limits only if stack overflow is observed in production.

- **Option D - Check on the way in; error if you cannot handle it**: When data arrives,
  confirm we can process it (size, shape, depth, and so on). After that, treat it as safe
  to walk. If something goes wrong during traversal, return an error — do not quietly skip
  parts of the data.

**Preferred option:** Option D

- **Check on the way in; error if you cannot handle it**: When data arrives,
  confirm we can process it (size, shape, depth, and so on). After that, treat it as safe
  to walk. If something goes wrong during traversal, return an error — do not quietly skip
  parts of the data.
---

### AP-7: Extra DB round-trips vs JOINs / single-query loading

**What it is**: After an initial query, related data is loaded via **multiple sequential**
SeaORM `load_*` calls (each call is typically **one batched SQL statement** for the whole
set, not per-row N+1) instead of fewer queries using JOINs or combined selects such as
`find_also_related()` / `find_with_related()`.

**Why it matters**: Each extra round-trip adds latency (often ~sum of sequential query
times vs ~max with parallelization, or ~one round-trip with a well-shaped JOIN). Distinct
from “missing batch load”: `load_one` on a `Vec<Model>` is already the standard SeaORM batch
pattern.

**Occurrences found (1)**:

| # | File | Line(s) | Description |
|---|------|---------|-------------|
| 1 | `modules/fundamental/src/purl/service/mod.rs` | ~602-626 | Four sequential `load_one` / `load_many_to_many` calls after one `all_statuses` query — four extra batched queries vs potentially one heavier JOIN (trade-off: clarity vs round-trips) |

> **Not included — micro-optimization**: `vulnerability/service/mod.rs` ~293 uses
> `advisories.load_one(organization::Entity, …)` which is a **single** batched query
> (one `WHERE id IN (…)` round-trip), not N+1. The overhead is one extra round-trip
> vs a JOIN on the initial advisory fetch — a minor optimization, not an anti-pattern.

**Convention options**:

- **Option A — Prefer fewer round-trips**: When relations can be loaded without an
  unacceptable cartesian product, prefer `.find_also_related()` / `.find_with_related()` or
  a shaped JOIN over **many sequential** batched `load_*` calls on the same parent set.
  Each `load_one`/`load_many` on a `Vec<Model>` is typically **one** SQL statement for the
  whole set (not per-row N+1); the trade-off is often **several batched queries vs one
  heavier JOIN**.

- **Option B — Optimize hot paths only**: Fewer round-trips / JOINs are recommended on
  API-facing read paths with measurable latency. Internal code may keep sequential batched
  `load_*` for clarity; profile before changing.

- **Option C — Keep as-is**: No convention. Sequential batched `load_one`/`load_many` is
  an acceptable default; JOIN consolidation is an optimization when profiling shows a need.

**Preferred Option:** - Option C

- **Keep as-is**: No convention. Sequential batched `load_one`/`load_many` is
  an acceptable default; JOIN consolidation is an optimization when profiling shows a need.
---

### AP-8: Missing Database Indexes

**What it is**: Frequently-queried columns that lack database indexes, causing full table
scans on filter and sort operations.

**Why it matters**: Without indexes, the database must scan every row for each query that
filters or sorts on these columns. As tables grow, query latency increases linearly.

**Occurrences found (2 tables)**:

| # | Table | Column(s) | Queried From | Impact |
|---|-------|-----------|-------------|--------|
| 1 | `product` | `name` | `ingestor/graph/product/mod.rs` — lookup by name during ingestion | Medium |
| 2 | `sbom_node` | `name` (exact-match) | `analysis/service/load/mod.rs` — `name.eq(...)` filters | Medium — **Note**: GIN trigram index `sbomnodenameginidx` exists (defined in `migration/src/m0000010_init_up.sql:3684`; serves `LIKE`/trigram queries) and migration `m0002100` adds a covering index on `(node_id) INCLUDE (sbom_id, name)`. Neither optimally serves **exact-match** `name = X` filters. A **name-leading B-tree** index may still help. |

> **Not included — already indexed**:
> - `base_purl (type, namespace, name)`: covered by `UNIQUE` constraint `package_type_namespace_name_key` plus GIN trigram indexes on each column
> - `organization.name`: covered by B-tree index `name_index`
> - `importer.name`: `name` is the primary key (`importer_pkey`)

**Convention options**:

- **Option A — Index all filtered/sorted columns**: Any column used in a `WHERE` or
  `ORDER BY` clause in production queries MUST have a database index. New endpoints that
  filter on unindexed columns must include a migration adding the index. Composite indexes
  should be created for multi-column filter patterns.

  ```sql
  -- Example: B-tree index for product name lookups
  CREATE INDEX IF NOT EXISTS idx_product_name
      ON product (name);
  ```

- **Option B — Index high-traffic columns only**: Indexes are required for columns used
  in public API endpoints that serve list/search results. Columns used only in low-traffic
  internal operations do not require indexes.

- **Option C — Keep as-is**: No convention. Index creation is decided per-query based on
  observed slow query logs. Premature indexing increases write overhead.

- **Option D — It depends; document pros and cons**: No single rule for every column.
  Before adding (or skipping) an index, write a short pros/cons list and decide from that.
  Typical factors:

  | For adding an index | Against adding an index |
  |---------------------|-------------------------|
  | Column is filtered or sorted often in production | Table is small or query volume is low |
  | Slow queries or full scans show up in logs | Writes are heavy; extra indexes slow inserts/updates |
  | Public API / user-facing latency matters | Existing indexes already cover the access pattern |
  | Table is large and still growing | Index would duplicate a UNIQUE constraint or unused composite |

  Record the decision in the PR or migration comment when it is not obvious.

  **Preferred option:** - Option D

  **It depends; document pros and cons**: No single rule for every column.
  Before adding (or skipping) an index, write a short pros/cons list and decide from that.
  Typical factors:

  | For adding an index | Against adding an index |
  |---------------------|-------------------------|
  | Column is filtered or sorted often in production | Table is small or query volume is low |
  | Slow queries or full scans show up in logs | Writes are heavy; extra indexes slow inserts/updates |
  | Public API / user-facing latency matters | Existing indexes already cover the access pattern |
  | Table is large and still growing | Index would duplicate a UNIQUE constraint or unused composite |

---

### Performance Anti-Pattern Summary

| # | Category | Occurrences | Recommended | Options |
|---|----------|-------------|-------------|---------|
| AP-1 | N+1 Queries | 5 | Prefer batch | Prefer batch; exceptions when impractical |
| AP-2 | Unbounded Queries | 3 | API pagination | Public API: `PaginatedResults`; internal may be unbounded if scoped |
| AP-3 | In-Memory Filtering | 0 (false positives removed) | — | A: SQL filters, B: Large datasets only, C: Keep |
| AP-4 | App-Side Counting | 0 | SQL `COUNT()` | Default `COUNT()`; `.len()` OK if rows already loaded |
| AP-5 | Missing Batch Ops | 0 | Bulk when many | Bulk for multiple; single op for single-item API |
| AP-6 | Recursive Traversal | 2 | Validate + error | Check on ingest; propagate errors; no silent skip |
| AP-7 | Extra round-trips vs JOINs | 1 | Keep as-is | Sequential batched `load_*`; JOIN if profiling says so |
| AP-8 | Missing Indexes | 2 tables | — | A: All filtered/sorted, B: High-traffic only, C: Keep, D: Pros/cons |

---

## Coding Anti-Pattern Analysis

In addition to performance anti-patterns, analysis of the codebase has identified recurring
coding anti-patterns that affect maintainability, correctness, and observability. This
section follows the same structure as the performance analysis above.

---

### CA-1: Swallowed Errors

**What it is**: Error values silently discarded via `.ok()`, `let _ =`, or `if let Ok(...)`
without logging or handling the error case. The caller has no signal that something went
wrong.

**Why it matters**: Silent error swallowing hides bugs, makes debugging difficult, and can
lead to data loss or inconsistent state. When a deserialization or DB write fails silently,
the system continues with missing or stale data.

**Occurrences found (9)**:

| # | File | Line(s) | Pattern | Severity |
|---|------|---------|---------|----------|
| 1 | `modules/importer/src/model/mod.rs` | ~331 | `serde_json::from_value(report).ok()` — importer run report deserialization silently dropped | High |
| 2 | `modules/importer/src/server/progress.rs` | ~48, 77 | `let _ = self.service.set_progress_message(...)` — DB write failures for progress silently discarded | High |
| 3 | `modules/importer/src/server/mod.rs` | ~186 | `serde_json::to_value(report).ok()` — importer run report serialization silently dropped on `update_finish`; report data lost from database | High |
| 4 | `modules/importer/src/model/mod.rs` | ~65 | `OffsetDateTime::from_unix_timestamp_nanos(t).ok()` — heartbeat timestamp errors silently dropped | Medium |
| 5 | `modules/ingestor/src/service/advisory/csaf/loader.rs` | ~44, 48 | `published`/`modified` timestamp conversions silently become `None` | Medium |
| 6 | `modules/ingestor/src/service/advisory/csaf/loader.rs` | ~62, 72 | CSAF version parsing silently dropped | Medium |
| 7 | `modules/ingestor/src/service/advisory/csaf/loader.rs` | ~166, 169 | `discovery_date`/`release_date` conversion errors silently dropped | Medium |
| 8 | `modules/importer/src/runner/{clearly_defined,clearly_defined_curation,cve,cwe,osv,quay}/mod.rs` | various | `serde_json::to_value(continuation).ok()` — serialization failure causes full re-import | Medium |
| 9 | `modules/ingestor/src/graph/sbom/cyclonedx.rs` | ~390, 395 | CPE/PURL parse failures silently skip items | Low |

> **Not included — verified false positives**:
> - `heartbeat.rs` ~43: `if let Ok(importer) = Heart::beat(...)` — the `else` branch explicitly
>   logs `log::debug!("Unable to acquire lock…")`. This is an expected optimistic-lock path,
>   not a swallowed error.
> - `sbom_group/service.rs` ~594, 630: `Uuid::parse_str(id).map_err(|_| NotFound)` — the
>   `Result` is propagated via `?`, not discarded. This is lossy error mapping (a 400-class
>   parse error disguised as 404), which may warrant a separate review, but it is not a
>   swallowed error.

**Convention options**:

- **Option A — Log all discarded errors**: Every `.ok()`, `let _ =`, and `if let Ok(...)`
  on a `Result` MUST be accompanied by a `tracing::warn!` or `tracing::debug!` log on the
  error path. Silent discarding of `Result` values is prohibited. Where the error case is
  intentionally ignored (e.g., format probing), add a code comment explaining why.

  ```rust
  // Approved: log the error before discarding
  match serde_json::from_value::<Report>(report) {
      Ok(r) => Some(r),
      Err(e) => {
          tracing::warn!("Failed to deserialize report: {e}");
          None
      }
  }

  // Prohibited: silent discard
  serde_json::from_value(report).ok()
  ```

- **Option B — Log on high-severity paths only**: Silent error discarding is prohibited
  on paths that affect data integrity (DB writes, state serialization, lock acquisition).
  Allowed on best-effort paths (timestamp formatting, display rendering) with a comment.

- **Option C — Keep as-is**: No convention. Developers judge whether an error is worth
  logging. `.ok()` is acceptable for non-critical conversions.

- **Option D — Handle by context (no one-size rule)**: Choose what to do based on the
  situation:

  1. **Instrumentation wrapper exists** — If tracing/metrics/instrumentation will
     record the failure, no extra logging or handling is required.
  2. **Return to the caller** — If the API or UI can surface the error to the caller, return
     or map it there. Do not also log the same failure redundantly.
  3. **Propagate** — If the error stops processing required data, propagate
     the error (`?`, `return Err(...)`) — do not swallow it.
  4. **Expected failure** — If failure is normal for this path (e.g. optimistic lock miss,
     optional field missing), ignoring it is fine; no log required.
  5. **Log before dropping** — If you must drop the error and cannot report it
     upstream, log it in a compact way (e.g. `.inspect_err(|e| tracing::debug!("…: {e}"))`)
     rather than a verbose `match`.

**Preferred option:** Option D

- **Handle by context (no one-size rule)**: Choose what to do based on the
  situation:

  1. **Instrumentation wrapper exists** — If tracing/metrics/instrumentation will
     record the failure, no extra logging or handling is required.
  2. **Return to the caller** — If the API or UI can surface the error to the caller, return
     or map it there. Do not also log the same failure redundantly.
  3. **Propagate** — If the error stops processing required data, propagate
     the error (`?`, `return Err(...)`) — do not swallow it.
  4. **Expected failure** — If failure is normal for this path (e.g. optimistic lock miss,
     optional field missing), ignoring it is fine; no log required.
  5. **Log before dropping** — If you must drop the error and cannot report it
     upstream, log it in a compact way (e.g. `.inspect_err(|e| tracing::debug!("…: {e}"))`)
     rather than a verbose `match`.
---

### CA-2: Stringly-Typed APIs

**What it is**: Using `String` or `&str` where a dedicated enum, newtype, or constant
would enforce type safety. Includes magic string comparisons and inconsistent string
prefix checks.

**Why it matters**: String comparisons are not checked at compile time. A typo in a status
string or an inconsistent prefix check creates bugs that only manifest at runtime and are
hard to trace.

**Occurrences found (5)**:

| # | File | Line(s) | Pattern | Severity |
|---|------|---------|---------|----------|
| 1 | `modules/fundamental/src/purl/service/mod.rs`, `modules/fundamental/src/purl/model/mod.rs` | ~693, ~171 | VEX status stored as `String`, manually matched to enum in two separate places | High |
| 2 | `modules/fundamental/src/purl/endpoints/base.rs`, `modules/fundamental/src/purl/endpoints/mod.rs` | ~39, ~60 | Inconsistent prefix check: `"pkg:"` vs `"pkg"` (missing colon) for pURL detection | High |
| 3 | `modules/fundamental/src/vulnerability/service/mod.rs` | ~79 | Sort field and direction compared as raw strings: `field == "id" && order == "asc"` — **Note**: constrained by the `Columns::translator` callback API (`fn(&str, &str, &str) -> Option<String>`); not fixable at the application level without framework changes | Medium |
| 4 | `modules/fundamental/src/sbom/endpoints/mod.rs` | ~372 | Hardcoded `vec!["affected".to_string()]` instead of enum | Low |
| 5 | `modules/fundamental/src/sbom/model/details.rs`, `modules/fundamental/src/vulnerability/service/mod.rs`, `modules/ingestor/src/graph/purl/status_creator.rs` | ~552, ~703, ~19 | `VexStatus` enum exists but multiple structs carry `status: String` | Medium |

**Convention options**:

- **Option A — Enums for fixed value sets**: Any value drawn from a fixed set (statuses,
  directions, relationship types) MUST be represented as a Rust enum, not a `String`. The
  enum is the single source of truth — string conversion happens only at serialization
  boundaries (API input/output, database columns). String matching against known values
  is prohibited.

  ```rust
  // Approved: enum with serde
  #[derive(Serialize, Deserialize, Clone, Debug)]
  #[serde(rename_all = "snake_case")]
  enum VexStatus { Affected, Fixed, NotAffected, UnderInvestigation, Recommended, /* ... */ }

  // Prohibited: string matching
  match status_string.as_str() {
      "affected" => ...,
      "fixed" => ...,
  }
  ```

- **Option B — Enums for domain values, strings for infrastructure**: Domain concepts
  (VEX status, relationship types) must use enums. Infrastructure strings (sort fields,
  filter keys) may remain as strings since they are validated by the query framework.

- **Option C — Keep as-is**: No convention. String-based matching is acceptable when the
  set of values is small and well-documented.

**Preferred option:** Option A

- **Enums for fixed value sets**: Any value drawn from a fixed set (statuses,
  directions, relationship types) MUST be represented as a Rust enum, not a `String`. The
  enum is the single source of truth — string conversion happens only at serialization
  boundaries (API input/output, database columns). String matching against known values
  is prohibited.

  ```rust
  // Approved: enum with serde
  #[derive(Serialize, Deserialize, Clone, Debug)]
  #[serde(rename_all = "snake_case")]
  enum VexStatus { Affected, Fixed, NotAffected, UnderInvestigation, Recommended, /* ... */ }

  // Prohibited: string matching
  match status_string.as_str() {
      "affected" => ...,
      "fixed" => ...,
  }
  ```

---

### CA-3: Code Duplication

**What it is**: Substantial logic blocks duplicated across modules with only the entity
type or minor details varying. Creates maintenance burden — a bug fix or behavior change
must be applied in multiple places.

**Why it matters**: Duplicated code diverges over time. One copy gets fixed, the other
doesn't. The more copies exist, the higher the probability of inconsistent behavior.

**Occurrences found (4)**:

| # | Files | Description | Severity |
|---|-------|-------------|----------|
| 1 | `modules/fundamental/src/advisory/service/mod.rs` ~132-197 vs `modules/fundamental/src/sbom/service/label.rs` ~16-77 | Nearly identical `set_labels`/`update_labels` with FOR UPDATE locking — differs only by entity type | High |
| 2 | `modules/fundamental/src/advisory/endpoints/label.rs` (~119 lines) vs `modules/fundamental/src/sbom/endpoints/label.rs` (~120 lines) | Identical label endpoint handlers — same `LabelQuery`, same `all`/`set`/`update` functions | High |
| 3 | `modules/fundamental/src/sbom/service/sbom.rs` ~222-268, ~338-390 and `modules/fundamental/src/purl/service/mod.rs` ~414-473 | Same SPDX+CycloneDX license filtering subquery pattern copied three times | Medium |
| 4 | `modules/fundamental/src/vulnerability/service/mod.rs` ~335-454, ~668-896 | `format_response`/`format_response_v2` share ~90% logic; `row_to_vuln_v3`/`v2` share ~40-50% (v3 has richer `AdvisoryEntry` with version_range, remediations, context_cpe) — significant duplication in the coordinators, moderate in the row mappers | Medium |

**Convention options**:

- **Option A — Extract shared logic into generics or traits**: When two or more modules
  implement the same logic pattern (e.g., label CRUD, license filtering), extract it into
  a shared generic function, trait, or macro parameterized by the entity type. Duplicated
  logic blocks longer than ~20 lines are prohibited.

  ```rust
  // Approved: generic label service
  async fn set_labels<E: EntityTrait>(
      entity_id: Uuid,
      labels: Labels,
      connection: &impl ConnectionTrait,
  ) -> Result<(), Error> { ... }
  ```

- **Option B — Extract only high-frequency duplications**: Only extract patterns that
  appear 3+ times or span 50+ lines. Two-instance duplication is acceptable if the
  entity-specific logic diverges enough that a generic would be complex.

- **Option C — Keep as-is**: No convention. Some duplication is acceptable for module
  autonomy. Each module owns its complete implementation without cross-module abstractions.

**Preferred option:** Option A

- **Extract shared logic into generics or traits**: When two or more modules
  implement the same logic pattern (e.g., label CRUD, license filtering), extract it into
  a shared generic function, trait, or macro parameterized by the entity type. Duplicated
  logic blocks longer than ~20 lines are prohibited.

  ```rust
  // Approved: generic label service
  async fn set_labels<E: EntityTrait>(
      entity_id: Uuid,
      labels: Labels,
      connection: &impl ConnectionTrait,
  ) -> Result<(), Error> { ... }
  ```

---

### CA-4: Tight Coupling Between Modules

**What it is**: Domain modules directly importing internal types from other domain modules,
creating a dependency web. Also, the `fundamental` (read) layer depending on `ingestor`
(write) layer types.

**Why it matters**: Tight coupling prevents independent evolution of modules, complicates
testing, and creates circular dependency risks. Changes to one module's internals cascade
to all importers.

**Occurrences found (3)**:

| # | File | Pattern | Severity |
|---|------|---------|----------|
| 1 | `sbom/model/details.rs` ~1-11 | SBOM model imports `AdvisoryHead`, `VulnerabilityHead`, `PurlSummary`, `StatusContext` from advisory, vulnerability, and purl modules | Medium |
| 2 | `vulnerability/model/details/vulnerability_advisory.rs` ~1-7 | Vulnerability model imports from advisory, purl, and sbom modules | Medium |
| 3 | `fundamental/*/service/mod.rs` (3 files: advisory, purl, vulnerability) | `fundamental` depends on `trustify_module_ingestor::common::Deprecation` — read layer depends on write layer | High |

**Convention options**:

- **Option A — Shared types in common crate**: Types used across multiple domain modules
  (e.g., `Deprecation`, `AdvisoryHead`, `VulnerabilityHead`) MUST live in `common/` or
  `entity/` crates, not in the module that happens to define them. Domain modules may only
  import from `common/`, `entity/`, and `query/` — never from sibling domain modules.

- **Option B — Allow read-model imports, prohibit layer violations**: Domain modules may
  import read-only model types (`*Head`, `*Summary`) from sibling modules for API response
  composition. However, the `fundamental` layer MUST NOT depend on `ingestor` — shared
  types like `Deprecation` must be moved to `common/`.

- **Option C — Keep as-is**: No convention. Cross-module imports are acceptable within
  `modules/fundamental/` since it is a single crate. The `Deprecation` import is a
  pragmatic trade-off.

**Preferred option:** - Option C

- **Keep as-is**: No convention. Cross-module imports are acceptable within
  `modules/fundamental/` since it is a single crate. The `Deprecation` import is a
  pragmatic trade-off.

---

### CA-5: Oversized Functions

**What it is**: Functions exceeding ~100 lines that perform multiple distinct phases
(query building, data loading, transformation, response construction) in a single body.

**Why it matters**: Long functions are harder to understand, test, and review. Each phase
is a separate concern that can be tested and evolved independently.

**Occurrences found (5)**:

| # | File | Function | Lines | Description |
|---|------|----------|-------|-------------|
| 1 | `sbom/model/details.rs` | `SbomDetails::from_entity` | ~367 | Builds 12+ JOIN query, executes raw SQL, extracts 8 ID sets, performs 9 bulk fetches, builds scores map |
| 2 | `vulnerability/service/mod.rs` | `build_query` | ~135 | Raw SQL UNION ALL construction with inline namespace branching and pURL parsing |
| 3 | `sbom/service/sbom.rs` | `fetch_sboms` | ~112 | Label filtering, group filtering, license subqueries, search config, pagination, mapping |
| 4 | `sbom/service/sbom.rs` | `fetch_sbom_packages` | ~122 | License filtering duplication plus package-specific query building |
| 5 | `vulnerability/service/mod.rs` | `row_to_vuln_v3` | ~130 | Inline struct definitions, JSONB deserialization, BTreeMap construction, advisory iteration |

**Convention options**:

- **Option A — Maximum function length**: Functions MUST NOT exceed 100 lines (excluding
  blank lines and comments). When a function has multiple distinct phases, extract each
  phase into a private helper method with a descriptive name. The parent function becomes
  a coordinator that calls the helpers in sequence.

- **Option B — Maximum cyclomatic complexity**: No hard line limit, but functions with
  more than 3 distinct phases (identifiable by blank-line-separated blocks or section
  comments) should be decomposed. Use judgment — a 150-line function with a single clear
  flow is better than 5 artificial 30-line helpers.

- **Option C — Keep as-is**: No convention. Function length is a style preference.
  Long functions are acceptable when the logic is linear and sequential.

**Preferred option:** - Option B

- **Maximum cyclomatic complexity**: No hard line limit, but functions with
  more than 3 distinct phases (identifiable by blank-line-separated blocks or section
  comments) should be decomposed. Use judgment — a 150-line function with a single clear
  flow is better than 5 artificial 30-line helpers.


---

### CA-6: Inconsistent Tracing Instrumentation

**What it is**: Some service methods in a file have `#[instrument]` attributes while
sibling methods in the same file do not. Endpoint handlers universally lack instrumentation.

**Why it matters**: Inconsistent instrumentation creates gaps in distributed traces. When a
request flows through an uninstrumented method, that segment becomes invisible in tracing
dashboards, making performance analysis and debugging harder.

**Occurrences found (8)**:

| # | File | Ratio | Gap |
|---|------|-------|-----|
| 1 | `advisory/service/mod.rs` | 1 of 5 | `fetch_advisory`, `delete_advisory`, `set_labels`, `update_labels` missing |
| 2 | `vulnerability/service/mod.rs` | 4 of 5 | `fetch_vulnerabilities` (main list endpoint) missing |
| 3 | `weakness/service/mod.rs` | 0 of 2 | All methods missing |
| 4 | `organization/service/mod.rs` | 0 of 2 | All methods missing |
| 5 | `product/service/mod.rs` | 0 of 3 | All methods missing |
| 6 | `sbom/service/sbom.rs` | 10 of 12 | `fetch_sboms` (main list endpoint) and `related_packages` missing |
| 7 | `purl/service/mod.rs` | 12 of 13 | `base_purls` missing |
| 8 | All endpoint handlers | 0% | No endpoint handler has `#[instrument]` |

**Convention options**:

- **Option A — Instrument all public service methods and endpoints**: Every `pub` or
  `pub(crate)` method on a service struct MUST have an `#[instrument]` attribute. Endpoint
  handlers MUST also be instrumented. Follow the conventions already in `CONVENTIONS.md`
  for `skip`, `skip_all`, and `err(level = ...)`.

- **Option B — Instrument service methods only**: All public service methods must have
  `#[instrument]`. Endpoint handlers are exempt because Actix-web middleware provides
  request-level tracing. Focus instrumentation on the service layer.

- **Option C — Keep as-is**: No convention. Instrumentation is added when needed for
  debugging. Partial coverage is acceptable.

- **Option D - Scoped to external work (see `docs/design/log_tracing.md`)**:
  Instrumentation is required where it matters, not on every `pub` method by default.
  Full detail is in the logging/tracing design doc; in short:

  - **Do instrument** — Logic that calls **external** systems (database, object storage,
    HTTP, message queues, etc.). Use `#[instrument]` on the enclosing block or function,
    or `.instrument(info_span!(...))` on individual awaits when one function has several
    load phases and inner helpers are not instrumented.
  - **Do not instrument** — Pure in-memory work that is **trivial** in context (simple
    mapping, formatting, small transforms).
  - **Do not double-wrap** — Pick one span per operation: either the outer function or an
    inner `.instrument` on the external call, not both for the same work.
  - **Scope by logic, not visibility** — Apply spans where external I/O happens, including
    non-`pub` helpers, not “every public method regardless of what it does.”

**Preferred Option:**: - Option D

- **Scoped to external work (see `docs/design/log_tracing.md`)**:
  Instrumentation is required where it matters, not on every `pub` method by default.
  Full detail is in the logging/tracing design doc; in short:

  - **Do instrument** — Logic that calls **external** systems (database, object storage,
    HTTP, message queues, etc.). Use `#[instrument]` on the enclosing block or function,
    or `.instrument(info_span!(...))` on individual awaits when one function has several
    load phases and inner helpers are not instrumented.
  - **Do not instrument** — Pure in-memory work that is **trivial** in context (simple
    mapping, formatting, small transforms).
  - **Do not double-wrap** — Pick one span per operation: either the outer function or an
    inner `.instrument` on the external call, not both for the same work.
  - **Scope by logic, not visibility** — Apply spans where external I/O happens, including
    non-`pub` helpers, not “every public method regardless of what it does.”

---

### CA-7: Missing Public API Documentation

**What it is**: Public structs, enums, traits, and functions without `///` doc comments.

**Why it matters**: Undocumented public APIs force readers to read the implementation to
understand behavior, parameters, and constraints. This slows onboarding, review, and
AI-assisted development.

**Occurrences found (7 service files with undocumented public types)**:

| # | File | Undocumented Items |
|---|------|--------------------|
| 1 | `advisory/service/mod.rs` | `AdvisoryService` struct, all 5 methods, `AdvisoryCatcher` struct |
| 2 | `vulnerability/service/mod.rs` | `VulnerabilityService` struct, all 5 methods |
| 3 | `weakness/service/mod.rs` | `WeaknessService` struct, both methods |
| 4 | `organization/service/mod.rs` | `OrganizationService` struct, both methods |
| 5 | `product/service/mod.rs` | `ProductService` struct, all 3 methods |
| 6 | `purl/service/mod.rs` | `PurlService` struct, most methods |
| 7 | `storage/src/service/mod.rs` | `StorageKey`, `StorageResult`, `StoreError` |

**Convention options**: - Option A

- **Option A — Document all public items**: Every public struct, enum, trait, function,
  and method MUST have a `///` doc comment. One line describing what it does is sufficient.
  Service methods should document their parameters, error conditions, and return value
  semantics when non-obvious.

- **Option B — Document service structs and complex methods**: Service structs and methods
  with non-trivial behavior (transactions, side effects, error handling nuances) must be
  documented. Simple getters and CRUD methods are self-documenting.

- **Option C — Keep as-is**: No convention. Documentation is optional and added at the
  author's discretion.

**Preferred option:**

- **Document all public items**: Every public struct, enum, trait, function,
  and method MUST have a `///` doc comment. One line describing what it does is sufficient.
  Service methods should document their parameters, error conditions, and return value
  semantics when non-obvious. Inside functions, add brief `//` comments only where the
  logic is not obvious from the code — keep them short; do not narrate every line.
---

### CA-8: Mixed Logging Frameworks (`log::` vs `tracing::`)

**What it is**: The same file uses both `log::debug!`/`log::warn!`/`log::info!` macros
and `tracing::instrument`/`tracing::Instrument` attributes, creating inconsistent
observability output.

**Why it matters**: The project enables the `tracing-log` bridge (`tracing-subscriber` with
the `"tracing-log"` feature in `common/infrastructure`), so `log::*` calls are forwarded to
`tracing` and do appear within spans. However, this forwarding is an implicit dependency —
mixing both frameworks creates confusion for contributors who may not know the bridge exists,
and adds cognitive overhead when reading code that uses two different APIs for the same purpose.
Standardizing on `tracing::` removes the ambiguity.

**Occurrences found (6)**:

| # | File | Pattern |
|---|------|---------|
| 1 | `vulnerability/service/mod.rs` | `log::debug!` (6 calls) mixed with `tracing::instrument` imports |
| 2 | `sbom/service/sbom.rs` | `log::debug!`, `log::warn!` mixed with `tracing::instrument` + `tracing::Instrument` |
| 3 | `purl/service/mod.rs` | `log::debug!` (2 calls) mixed with `tracing::{instrument, Instrument, info_span}` |
| 4 | `analysis/src/service/mod.rs` | `log::info!`, `log::warn!`, `log::debug!`, `log::trace!` (11 calls) mixed with `tracing::instrument` |
| 5 | `advisory/endpoints/mod.rs` | `log::warn!`, `log::info!` only (no `tracing::` in this file) — module-level inconsistency: advisory *service* uses `tracing::instrument` while advisory *endpoints* uses `log::` only |
| 6 | `ingestor/src/service/mod.rs` | `log::debug!`, `log::warn!` mixed with `tracing::instrument` |

**Convention options**:

- **Option A — Use `tracing::` exclusively**: All logging MUST use `tracing::` macros
  (`tracing::debug!`, `tracing::warn!`, `tracing::info!`, `tracing::error!`). Remove the
  `log` crate dependency. Existing `log::*` calls must be migrated to `tracing::*`.

  ```rust
  // Approved
  tracing::debug!("Processing vulnerability {id}");

  // Prohibited
  log::debug!("Processing vulnerability {id}");
  ```

- **Option B — Standardize per module**: Each module must use one framework consistently.
  New code must use `tracing::`. Existing `log::` usage is migrated opportunistically
  when the file is modified for other reasons.

- **Option C — Keep as-is**: No convention. Both `log::` and `tracing::` are acceptable.
  The `tracing` compatibility layer forwards `log` events to tracing subscribers.


- **Preferred Option** - Option A

**Use `tracing::` exclusively**: All logging MUST use `tracing::` macros
  (`tracing::debug!`, `tracing::warn!`, `tracing::info!`, `tracing::error!`). Remove the
  `log` crate dependency. Existing `log::*` calls must be migrated to `tracing::*`.

  ```rust
  // Approved
  tracing::debug!("Processing vulnerability {id}");

  // Prohibited
  log::debug!("Processing vulnerability {id}");
  ```
---

### CA-9: Magic Numbers and Hardcoded Values

**What it is**: Numeric constants, string literals, or URLs embedded directly in code
without named constants, making their meaning opaque and changes error-prone.

**Why it matters**: A magic number like `13` or a hardcoded URL must be understood from
context. If the value needs to change, every occurrence must be found and updated.

**Occurrences found (4)**:

| # | File | Line(s) | Pattern | Severity |
|---|------|---------|---------|----------|
| 1 | `modules/fundamental/src/sbom/model/raw_sql.rs` | ~15, 48, 63 | `AND relationship = 13` in raw SQL — no comment explaining what type 13 is | High |
| 2 | `modules/ingestor/src/service/advisory/cve/divination.rs` | ~14 | Hardcoded `"https://repo.maven.apache.org/maven2/"` URL for heuristic matching — magic string (well-known canonical URL, but embedded in function logic rather than a named constant) | Low |
| 3 | `modules/ingestor/src/graph/mod.rs` | ~86 | `"duplicate key value violates unique constraint"` — fragile string matching on DB error message | Medium |
| 4 | `modules/importer/src/server/context.rs` | ~33 | `Duration::from_secs(20)` timeout without named constant | Low |

**Convention options**:

- **Option A — Named constants for all magic values**: All numeric literals, string
  literals used for comparison, and duration values MUST be defined as named constants
  (`const` or `static`) with a descriptive name and a doc comment. Raw SQL relationship
  types must use constants that reference the enum or migration that defines them.

  ```rust
  /// SBOM relationship type "describes" as defined in migration m0001234
  const RELATIONSHIP_DESCRIBES: i32 = 13;

  // In raw SQL
  format!("AND relationship = {RELATIONSHIP_DESCRIBES}")
  ```

- **Option B — Named constants for domain values only**: Domain-specific magic values
  (relationship types, status codes, heuristic thresholds) must use named constants.
  Infrastructure values (timeouts, poll intervals) may be inline if used only once.

- **Option C — Keep as-is**: No convention. Inline values are acceptable with explanatory
  comments.

- **Option D - It depends; use judgment**: Prefer named constants when they clarify
meaning. Skip extracting a constant when it adds noise or hurts clarity:

  - **Inline in SQL strings** — e.g. `relationship = 13` in raw SQL: pulling `13` into a
    `const` that is interpolated with `format!` can force string rendering on every use
    instead of a static SQL fragment. Prefer leaving the literal in the SQL and a short
  comment explaining **why** that value is there (which enum/migration it matches).
  - **Single-use imports** — e.g. `DEFAULT_SOURCE_CVEPROJECT` imported from another module
    but only used once in an `ImporterConfiguration::Cve(...)` block: keep the value in
    the same file for readability unless it is genuinely reused elsewhere; then refactor to
    a shared constant.

**Preferred option:**: Option D
 - **It depends; use judgment**: Prefer named constants when they clarify
  meaning. Skip extracting a constant when it adds noise or hurts clarity:

  - **Inline in SQL strings** — e.g. `relationship = 13` in raw SQL: pulling `13` into a
    `const` that is interpolated with `format!` can force string rendering on every use
    instead of a static SQL fragment. Prefer leaving the literal in the SQL and a short
  comment explaining **why** that value is there (which enum/migration it matches).
  - **Single-use imports** — e.g. `DEFAULT_SOURCE_CVEPROJECT` imported from another module
    but only used once in an `ImporterConfiguration::Cve(...)` block: keep the value in
    the same file for readability unless it is genuinely reused elsewhere; then refactor to
    a shared constant.
---

### CA-10: Raw SQL Defeating Parameterization

**What it is**: Building SQL queries by concatenating parameterized sub-queries into a
single string, which inlines parameter values as string literals and defeats the
parameterization that prevents SQL injection and enables query plan caching.

**Why it matters**: Inlined parameters prevent the database from reusing query plans and
remove a layer of SQL injection protection. While the current code parameterizes sub-queries
individually, the final concatenation undoes this.

**Occurrences found (1)**:

| # | File | Line(s) | Description |
|---|------|---------|-------------|
| 1 | `modules/fundamental/src/vulnerability/service/mod.rs` | ~455-657 | `build_vulnerabilities_query_string` (~455-521) uses `format!()` to interpolate SQL fragments; `build_query` (~523-657) constructs sub-queries with `Statement::from_sql_and_values`, then `.to_string()`s them and concatenates with `UNION ALL` into a `Statement::from_string` |

**Convention options**:

- **Option A — Prohibit `Statement::from_string` with concatenated queries**: All SQL
  queries MUST use parameterized statements end-to-end. If `UNION ALL` is needed, use
  SeaORM's `UnionType` builder or a single parameterized CTE. `Statement::from_string`
  is only acceptable for static SQL with no dynamic values.

- **Option B — Allow with review gate**: `Statement::from_string` with dynamic content
  is allowed but must be flagged with a `// SAFETY:` comment explaining why
  parameterization is not possible and confirming that all interpolated values are
  validated. Such code requires explicit reviewer approval.

- **Option C — Keep as-is**: No convention. The current pattern is safe because the values
  come from internal code, not user input. Query plan caching is not a priority.

**Preferred option:**: - Option B

- **Allow with review gate**: `Statement::from_string` with dynamic content
  is allowed but must be flagged with a `// SAFETY:` comment explaining why
  parameterization is not possible and confirming that all interpolated values are
  validated. Such code requires explicit reviewer approval.


---

### CA-11: Database Resource Conventions

**What it is**: Inconsistent or undocumented patterns for creating database resources —
tables, columns, enums, indexes, foreign keys, and migrations — leading to naming
divergence, missing constraints, and schema that is hard to evolve.

**Why it matters**: The database schema is the foundation of the system. Inconsistent naming
makes queries and entity mappings harder to follow. Missing or misapplied column types
(e.g., using `String` where a PostgreSQL `ENUM` is warranted) defeat type safety at the
storage layer. Migrations without idempotency guards break re-runs. Foreign keys without
appropriate `ON DELETE` actions cause orphaned rows or unexpected cascading deletes.

This section catalogs the conventions derived from existing Trustify schema patterns and
codifies them as the standard for new database work.

---

#### CA-11.1: Table and Column Naming

**Convention**: All database object names use `snake_case`.

| Object | Convention | Example |
|--------|-----------|---------|
| Tables | Singular noun or compound noun | `sbom`, `advisory_vulnerability`, `source_document` |
| Columns | Descriptive noun/noun-phrase | `sbom_id`, `node_id`, `vulnerability_id`, `published` |
| Join/association tables | `<left>_<right>` or domain term | `sbom_package_purl_ref`, `product_version` |

**Anti-pattern**: CamelCase, pluralized table names, or abbreviated column names that
lose meaning (e.g., `vulnId`, `src_doc`, `Advisories`).

```sql
-- Approved
CREATE TABLE advisory_vulnerability (
    advisory_id UUID NOT NULL,
    vulnerability_id VARCHAR NOT NULL
);

-- Prohibited
CREATE TABLE AdvisoryVulnerabilities (
    advId UUID NOT NULL,
    vulnID VARCHAR NOT NULL
);
```

---

#### CA-11.2: Column Types

**Convention**: Use the narrowest correct PostgreSQL type. Trustify standard mappings:

| Data | PostgreSQL Type | Rust / SeaORM | Notes |
|------|----------------|---------------|-------|
| Primary keys (default) | `UUID` | `Uuid` with `#[sea_orm(primary_key)]` | Default `gen_random_uuid()` in migration |
| Primary keys (domain id) | `VARCHAR` / `TEXT` | `String` with `#[sea_orm(primary_key)]` | When the domain defines a natural key (e.g., `vulnerability.id` stores CVE IDs as `String`) |
| Foreign keys | Same type as referenced PK | `Uuid` / `String` | Must match the referenced column exactly |
| Timestamps | `TIMESTAMP WITH TIME ZONE` | `OffsetDateTime` / `Option<OffsetDateTime>` | Always timezone-aware; never bare `TIMESTAMP` |
| Free text | `TEXT` | `String` / `Option<String>` | `TEXT`|
| Structured data | `JSONB` | `serde_json::Value` with `#[sea_orm(column_type = "JsonBinary")]` | Use `FromJsonQueryResult` for typed deserialization |
| Arrays | `TEXT[]` | `Vec<String>` | Only for simple homogeneous lists (e.g., CWE IDs) |
| Booleans | `BOOLEAN` | `bool` | Use `NOT NULL DEFAULT false` — avoid nullable booleans |
| Scores / metrics | `DOUBLE PRECISION` or `REAL` | `f64` / `f32` | Match upstream data precision |
| Counters / sizes | `BIGINT` | `i64` | For file sizes, row counts |
| Integer values | `INTEGER` | `i32` | Used for integer-backed enums (e.g., `relationship`, `external_type`), importer state, and discriminators |
| Fixed value sets | PostgreSQL `ENUM` | `DeriveActiveEnum` | See CA-11.3 |

**Anti-pattern**: Using `String` for a column that holds values from a fixed set (use an
ENUM or lookup table — see CA-11.3), using `TIMESTAMP` without time zone, or using
`INTEGER` for a primary key without a domain reason (prefer `UUID` or a domain-natural
`String` key).

---

#### CA-11.3: Enums

**Convention**: Prefer storing fixed value sets as a typed construct rather than bare
`VARCHAR`/`TEXT` columns. The codebase uses three patterns — choose the one that fits:

| Pattern | When to use | Example |
|---------|-------------|---------|
| **PostgreSQL ENUM** | Small, rarely-changing set of string values | `score_type`, `cvss3_severity`, `crypto_asset_type` |
| **Integer-backed `DeriveActiveEnum`** | Performance-sensitive columns or sets managed in Rust code with numeric identity | `relationship` (`rs_type = "i32"`, `db_type = "Integer"`, `num_value = 0..15`) |
| **Lookup table** | Set that grows over time or carries extra metadata (description, URL) | `version_scheme` (rows added by data migrations, e.g., `m0002080`); `status` (VEX status values referenced by `purl_status.status_id` and `product_status.status_id`) |

**PostgreSQL ENUM example** (most common for CVSS-style values):

**Migration side** — define the type in SQL:

```sql
CREATE TYPE score_type AS ENUM ('2.0', '3.0', '3.1', '4.0');
```

**Entity side** — map it in Rust:

```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "score_type")]
pub enum ScoreType {
    #[sea_orm(string_value = "2.0")]
    V2_0,
    #[sea_orm(string_value = "3.0")]
    V3_0,
    #[sea_orm(string_value = "3.1")]
    V3_1,
    #[sea_orm(string_value = "4.0")]
    V4_0,
}
```

**Integer-backed enum example** (used for `relationship`):

```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum Relationship {
    #[sea_orm(num_value = 0)]
    Contains,
    #[sea_orm(num_value = 13)]
    Describes,
    // ...
}
```

**Naming**: Enum type names use `snake_case` (e.g., `cvss3_severity`, `crypto_asset_type`).
Enum variant string values use the domain's canonical representation (e.g., `"3.1"` for
CVSS version, `"kebab-case"` for asset types).

**Anti-pattern**: Storing enum-like values as bare `VARCHAR`/`TEXT` columns without any
typed backing (no PG ENUM, no integer mapping, no lookup table). This allows invalid values
at the database level and pushes validation entirely to application code.

---

#### CA-11.4: Indexes

**Convention**: Indexes follow these rules:

| Rule | Detail |
|------|--------|
| **Naming** | Prefer `<table>_<column(s)>_idx` in snake_case (e.g., `advisory_vulnerability_vulnerability_id_idx`). Existing indexes use several variants (`idx_` prefix, descriptive names, no `_idx` suffix) — new indexes should follow the `<table>_<col>_idx` convention for consistency |
| **Idempotency** | Always use `.if_not_exists()` (SeaORM) or `CREATE INDEX IF NOT EXISTS` (SQL) |
| **B-tree** | Default index type for equality and range queries on scalar columns |
| **GIN** | Use for JSONB containment queries (`@>`), `LIKE`/trigram searches, and array columns |
| **Composite** | Create composite indexes when queries frequently filter on multiple columns together; column order follows query selectivity (most selective first) |

**When to index** — follow AP-8 (Option D: pros/cons analysis):

```rust
// Real example: migration/src/m0001060_advisory_vulnerability_indexes.rs
Index::create()
    .if_not_exists()
    .table(AdvisoryVulnerability::Table)
    .name(Indexes::AdvisoryVulnerabilityVulnerabilityIdIdx.to_string())
    .col(AdvisoryVulnerability::VulnerabilityId)
    .to_owned()
```

**Anti-pattern**: Creating indexes without `IF NOT EXISTS`, using auto-generated index names
that are hard to reference, or adding indexes on every column without considering write
overhead (see AP-8).

**Index naming convention options**:

The codebase has ~90 indexes across 4 naming patterns: `<table>_<col>_idx` suffix (~32,
dominant in early migrations), `idx_<descriptive>` prefix (~18, dominant in newer migrations
like m0001210, m0002110, m0002180), legacy camelCase GIN names (~22, e.g.,
`basepurlnameginidx`), and descriptive names (~11, e.g., `by_id_and_version`, `name_index`).
Legacy indexes are not renamed in any option.

- **Option A — `<table>_<col(s)>_idx` suffix for new indexes**: Matches the majority of
  existing indexes and the current Naming row above.

- **Option B — `idx_<table>_<col(s)>` prefix for new indexes**: Matches the pattern used
  in newer migrations (m0001210, m0002110, m0002140, m0002180).

- **Option C — Keep as-is**: No naming convention enforced. Each migration author picks a
  name.

**Preferred option:** Awaiting decision

---

#### CA-11.5: Foreign Keys and Constraints

**Convention**:

| Constraint | Rule |
|------------|------|
| **Foreign keys** | Every column referencing another table MUST have an explicit `FOREIGN KEY` constraint |
| **ON DELETE** | Choose the action deliberately — `CASCADE` for child-lifecycle-tied-to-parent (e.g., `sbom_node` → `sbom`), `RESTRICT` for prevent-delete-if-children-exist, `SET NULL` for nullable optional references |
| **UNIQUE** | Add `UNIQUE` constraints for natural keys or business identifiers (e.g., `advisory.identifier`) |
| **NOT NULL** | Columns are `NOT NULL` by default; use `Option<T>` / `NULL` only when the absence of a value is a valid domain state |
| **ON UPDATE** | Not used — primary keys (UUID and domain-natural `String` keys) are treated as immutable. All foreign keys default to `NO ACTION` on update |

```rust
// Approved: explicit foreign key with cascade
Table::create()
    .table(SbomAi::Table)
    .col(ColumnDef::new(SbomAi::SbomId).uuid().not_null())
    .foreign_key(
        ForeignKey::create()
            .from_col(SbomAi::SbomId)
            .to(Sbom::Table, Sbom::SbomId)
            .on_delete(ForeignKeyAction::Cascade),
    )
```

**Anti-pattern**: Omitting foreign key constraints ("we'll enforce it in application code"),
defaulting to `CASCADE` without considering whether child rows should actually be deleted
when the parent is removed, or making columns nullable without a domain reason.

---

#### CA-11.6: Migrations

**Convention**:

| Rule | Detail |
|------|--------|
| **File naming** | `m<7-digit-number>_<description>.rs` (e.g., `m0002030_create_ai.rs`) |
| **Numbering** | Convention: increment by 10 (e.g., `m0002190` → `m0002200`) to leave room for insertions. The next number is the highest existing migration + 10. Range boundaries (0→1000→2000) reflect natural development phases, not enforced partitions |
| **SQL files** | Complex SQL goes in a same-named directory loaded via `include_str!()` |
| **Idempotency** | Use `IF NOT EXISTS` / `IF EXISTS` guards — strongest on indexes and column additions (`.if_not_exists()`, `add_column_if_not_exists()`). For new table creation, many existing migrations omit `.if_not_exists()` since SeaORM's migration runner tracks execution state; prefer adding it for safety in new migrations |
| **Up and down** | Implement both `up()` and `down()` for reversibility |
| **Schema vs. data** | Schema migrations registered with `.normal()`; data backfills registered with `.data()` and run separately via `trustd db data <names>` |
| **Prefer no data in schema migrations** | Schema migrations should avoid inserting, updating, or deleting application data rows — use `.data()` migrations for that. Legacy exceptions exist (e.g., `m0001000` updates `sbom`, `m0002080` inserts into `version_scheme`, `m0002170` updates `vulnerability`), but new migrations should separate schema from data |

```rust
// Approved: migration with idempotency
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(
            Table::create()
                .table(NewEntity::Table)
                .if_not_exists()
                .col(ColumnDef::new(NewEntity::Id).uuid().not_null().primary_key())
                .col(ColumnDef::new(NewEntity::Name).string().not_null())
                .to_owned(),
        ).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(
            Table::drop().table(NewEntity::Table).if_exists().to_owned(),
        ).await
    }
}
```

**Anti-pattern**: Migrations without idempotency guards on indexes or column additions
(fails on re-run), mixing data manipulation into schema migrations without justification,
or skipping `down()` (makes rollback impossible).

---

**Preferred convention**: All sub-sections above (CA-11.1 through CA-11.7) represent the
dominant project patterns extracted from existing code. They apply as the target standard
for new database work. Some legacy deviations exist (noted inline) — these are not
retroactive violations, but new code should follow the conventions documented here.

---

### Coding Anti-Pattern Summary

| # | Category | Occurrences | Recommended | Options |
|---|----------|-------------|-------------|---------|
| CA-1 | Swallowed Errors | 9 | By context (D) | Handle by instrumentation / propagate / log / ignore rules |
| CA-2 | Stringly-Typed APIs | 5 | Enums (A) | Enums for fixed value sets |
| CA-3 | Code Duplication | 4 | Extract shared (A) | Generics/traits for ~20+ line duplicates |
| CA-4 | Tight Coupling | 3 | Keep as-is (C) | Cross-imports OK within `fundamental` |
| CA-5 | Oversized Functions | 5 | Decompose (B) | Split when >3 distinct phases; judgment on line count |
| CA-6 | Inconsistent Tracing | 8 gaps | External I/O (D) | Instrument DB/storage/HTTP; skip trivial; no double-wrap (`log_tracing.md`) |
| CA-7 | Missing Documentation | 7 files | Document (A) | Public `///`; brief non-obvious `//` inside functions |
| CA-8 | Mixed Logging | 6 files | `tracing` only (A) | Migrate `log::` to `tracing::` |
| CA-9 | Magic Numbers | 4 | It depends (D) | Named constants when they clarify; exceptions documented |
| CA-10 | Raw SQL Parameterization | 1 | Review gate (B) | `// SAFETY:` + reviewer approval for `from_string` concat |
| CA-11 | Database Resource Conventions | — | Codified (most); index naming awaiting decision | Tables, columns, enums, indexes (naming: A/B/C), FKs, migrations |

> **Next step**: Selected conventions will be added to
> [`CONVENTIONS.md`](../../CONVENTIONS.md) in a follow-up commit. AP-3 (in-memory filtering)
> remains open for maintainer decision.

## References

- [Trustify CONVENTIONS.md](../../CONVENTIONS.md) — the conventions file introduced by this ADR
- [TC-4289](https://redhat.atlassian.net/browse/TC-4289) — Jira task for architectural standards
