# Coding Conventions

## Code Style

- Formatting and lint policy are enforced by `cargo xtask precommit` — see [Pre-commit Checks](#pre-commit-checks)
- `unwrap()`, `expect()`, and `panic!()` are denied in production code but allowed in tests — see `.clippy.toml`.
- `todo!()` and `unimplemented!()` are denied everywhere, including tests — see `xtask/src/precommit.rs`.

### Import Nesting

Merge multiple `use` statements from the same crate into a single `use` block with nested
paths. This reduces visual clutter and groups related imports.

```rust
// Good — single nested use block
use sea_orm::{error::DbErr, ConnectionTrait, TransactionTrait};

// Avoid — separate use statements from the same crate
use sea_orm::error::DbErr;
use sea_orm::{ConnectionTrait, TransactionTrait};
```

This is a manual convention — `rustfmt`'s `imports_granularity = "Crate"` option is not
available on the stable channel. Reviewers should flag un-nested imports during code review.

### Import Style

Always bring items into scope with a `use` import — types, functions, and traits alike.

```rust
// Good
use crate::graph::db_context::parse_status;
use std::iter::once;
parse_status(value)?;
let ids = once(winner.base.id);

// Avoid — inline qualified paths
crate::graph::db_context::parse_status(value)?;
let ids = std::iter::once(winner.base.id);
```

**Exception — ambiguous names:** Common names that appear in many modules should stay
qualified with a short (1–2 segment) path, even when there is no conflict in the current
file. This keeps the code self-documenting:

```rust
// Good — qualified to avoid ambiguity
let model: advisory_vulnerability::Model = ...;
let result: std::fmt::Result = ...;
let value = serde_json::from_value(...);

// Avoid — bare name is ambiguous across modules
let model: Model = ...;
```

Names that benefit from qualification include `Model`, `Entity`, `Column`, `ActiveModel`,
`Relation`, `from_value`, `info`, and similar names that appear in many modules.

**Enforcement:** Clippy catches long qualified paths using the threshold configured in
`.clippy.toml`. Shorter paths are caught during code review.

## Naming Conventions

- Entity models: `Model` struct inside each entity module, table names are snake_case (`sbom`, `advisory`, `sbom_group`)
- Service structs: `<Domain>Service` (e.g., `SbomService`, `AdvisoryService`)
- Endpoint functions: short verbs — `get`, `all`, `delete`, `upload`, `download`, `packages`, `related`
- API routes: `/v3/<resource>` (e.g., `/v3/sbom`, `/v3/advisory/{key}`)
- OpenAPI operation IDs: camelCase (`getSbom`, `listSboms`)

## File Organization

### Domain module structure (e.g., `modules/fundamental/src/sbom/`)

Each domain area follows the same three-submodule pattern:

```
<domain>/
  mod.rs                # Re-exports: pub mod endpoints, service, model
  endpoints/
    mod.rs              # configure() function, endpoint handlers
    test.rs             # Endpoint integration tests (#[cfg(test)])
    label.rs            # Label sub-endpoints (if applicable)
    query.rs            # Query parameter structs
    config.rs           # Endpoint config structs
  service/
    mod.rs              # <Domain>Service struct with pub methods
    test.rs             # Service integration tests (#[cfg(test)])
    <submodule>.rs      # Additional service logic
  model/
    mod.rs              # API response/request models (DTOs)
    details.rs          # Detailed model variants
```

### Entity files

One file per database table in `entity/src/` (e.g., `sbom.rs`, `advisory.rs`, `sbom_group.rs`).

### Migration files

Named `m<7-digit-number>_<description>.rs` (e.g., `m0002030_create_ai.rs`). SQL files go in a directory with the same name when needed.

## Error Handling

- Each module defines its own `Error` enum in `error.rs`, using `#[derive(Debug, thiserror::Error)]`
- Common error variants: `Database(DbErr)`, `Query(query::Error)`, `NotFound(String)`, `BadRequest(...)`, `Any(anyhow::Error)`
- Every module error implements `actix_web::ResponseError` to map errors to HTTP status codes
- `From<DbErr>` is implemented manually (not via `#[from]`) to handle `RecordNotFound` → `NotFound` conversion
- Use `?` with automatic `From` conversions throughout service and endpoint code
- Endpoints return `actix_web::Result<impl Responder>`
- Internal library functions (non-endpoint, non-`main`) must return typed errors using
  `thiserror`-derived enums, not `anyhow::Result`. Use named variants with `#[source]` on
  wrapped causes so callers can match on specific error cases and error chains remain
  inspectable. `anyhow` is appropriate only at application boundaries (CLI entry points,
  `main`, test helpers) where structured matching is not needed.

```rust
// Good — typed error in library code
use std::io::Error;

#[derive(Debug, thiserror::Error)]
enum ResolveError {
    #[error("failed to read file '{path}': {source}")]
    FileRead { path: String, #[source] source: Error },
}
fn resolve(path: &str) -> Result<String, ResolveError> { ... }

// Avoid — anyhow in library code hides error structure from callers
fn resolve(path: &str) -> anyhow::Result<String> { ... }
```

## Testing Conventions

- Integration tests use `#[test_context(TrustifyContext)]` from the `trustify_test_context` crate
- Test functions are `async fn` annotated with `#[test(actix_web::test)]`
- Tests return `anyhow::Result<()>` for ergonomic error handling
- Tests live in `test.rs` files alongside the code they test, gated by `#[cfg(test)] mod test;`
- Endpoint tests use `TestRequest` builder pattern to construct HTTP requests and `call_service` to execute
- Service tests call service methods directly against a test database
- Test data is ingested via `TrustifyContext` methods such as `ingest_document` / `ingest_documents`; use the crate-level `document_bytes` helper when you need raw fixture bytes
- The `TrustifyContext` provides: `db`, `graph`, `storage`, `ingestor` fields
- Inline unit tests (e.g., in `sbom.rs`) use `#[cfg(test)] mod test { ... }` blocks

## Commit Messages

- Follow Conventional Commits: `<type>[optional scope]: <description>`
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
- Reference the Jira issue in the commit footer (e.g., `Implements TC-123`)
- AI-assisted commits include an `Assisted-by: <tool> (<model>)` trailer (e.g., `--trailer="Assisted-by: OpenCode (GPT-6.1 Sol)"`). Name both the harness and the model that produced the change.

## Pre-commit Checks

Run the full gate before every commit:

```sh
cargo xtask precommit
```

It regenerates JSON schemas and `openapi.yaml`, runs clippy, applies formatting, and
checks compilation. Commit any files it modifies (schemas, `openapi.yaml`).

Source of truth: `xtask/src/precommit.rs` — do not run the individual steps separately.

## CLI Argument Patterns

- Use `value_parser` to parse CLI arguments directly into their target type rather than accepting `String` and converting later. This moves validation to parse time and produces clear clap error messages on startup.

  ```rust
  // Good — parse and validate at arg-parse time
  #[arg(long, env = "TRUSTD_FOO", value_parser = parse_foo)]
  pub foo: Vec<MyType>,

  fn parse_foo(s: &str) -> Result<MyType, String> { ... }

  // Avoid — accept String, convert/validate later in business logic
  #[arg(long, env = "TRUSTD_FOO", value_delimiter = ',')]
  pub foo: Vec<String>,
  ```

## Endpoint Patterns

- Endpoints are registered in a `configure()` function that takes `ServiceConfig`, the `ReadOnly` and/or `ReadWrite` connection types, and config params
- Services are injected via `web::Data<T>` (Actix application data)
- Authorization uses `Require<Permission>` extractor or `authorizer.require(&user, Permission::...)` call
- Read operations use the `ReadOnly` connection: `let tx = db.begin().await?;`
- Write operations use the `ReadWrite` connection and its `transaction()` method
- List endpoints accept `Query` (search/filter), `Paginated` (pagination), and return `PaginatedResults<T>`
- Every endpoint has a `#[utoipa::path(...)]` attribute for OpenAPI documentation with `tag`, `operation_id`, `params`, and `responses`
- Route attributes use Actix macros: `#[get("/v3/...")]`, `#[post("/v3/...")]`, `#[delete("/v3/...")]`

### DELETE Idempotency

All DELETE endpoints return `204 No Content` regardless of whether the resource existed.
Deleting a non-existent resource is a successful no-op, not a 404 error. This makes
DELETE operations idempotent — callers do not need to check existence before deleting,
and concurrent or repeated deletes are safe.

**Exception — `If-Match` revision checks:** When a DELETE request includes an `If-Match`
header, the server validates the provided revision against the current resource state.
If the revisions do not match (including when the resource does not exist but a specific
revision was provided), the server returns `412 Precondition Failed`. When `If-Match: *`
is used (or the header is omitted), the idempotent 204 behavior applies.

## Entity Model Patterns

- Entities use `#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]` with `#[sea_orm(table_name = "...")]`
- Primary keys annotated with `#[sea_orm(primary_key)]`
- Relations defined via `impl Related<T> for Entity` with `fn to()` and optionally `fn via()`
- Link structs (e.g., `SbomPurlsLink`) implement `Linked` for many-to-many joins
- `ActiveModelBehavior` is implemented (usually empty) for each entity
- API response models (DTOs) in `model/` use `#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]`

## Migration Patterns

- Use SeaORM migration framework (`MigrationTrait`)
- Index creation uses `.if_not_exists()` for idempotency
- Function definitions use `CREATE OR REPLACE FUNCTION`
- Column additions use `add_column_if_not_exists()`
- Drop operations use `.if_exists()`
- Raw SQL loaded via `include_str!("migration_dir/up.sql")`
- Migrations must implement `down()` for reversibility — the migration module tests verify this (e.g., by running `refresh()`, which executes down + up on every migration)
- Data migrations are separate from schema migrations, run via `trustd db data <names>`

## Rust Idioms

### Borrowed keys for map lookups

When creating ephemeral structs used only as map keys (e.g., for `HashMap::get()`), prefer
borrowed references (`&str`) over owned strings (`String`) to avoid unnecessary allocations:

```rust
// Good — no allocations for lookups
#[derive(Clone, PartialEq, Eq, Hash)]
struct PurlKey<'a> {
    ty: &'a str,
    namespace: Option<&'a str>,
    name: &'a str,
}

// Avoid — clones strings just to build a lookup key
#[derive(Clone, PartialEq, Eq, Hash)]
struct PurlKey {
    ty: String,
    namespace: Option<String>,
    name: String,
}
```

### Pairwise iteration with `.zip()`

Use `.zip()` instead of `enumerate()` plus index access when iterating two collections
in lockstep. Indexing panics if the second collection is shorter; `.zip()` stops at the
shorter collection. Validate lengths first if every item must have a partner.

```rust
for (item, status) in items.iter().zip(statuses.iter()) {
    process(item, status);
}
```

## SeaORM Query Patterns

### Filtering by column values

Use `.is_in()` for filtering by a set of values instead of chaining multiple `.add()` / OR
conditions:

```rust
// Good
.filter(purl_status::Column::BasePurlId.is_in(base_ids))

// Avoid — verbose and generates excessive query parameters
let mut condition = Condition::any();
for id in &base_ids {
    condition = condition.add(purl_status::Column::BasePurlId.eq(*id));
}
```

### Query parameter limits and chunking

PostgreSQL has a hard limit of 65535 bind parameters per query. Queries that build conditions
from user-provided or large data sets (e.g., filtering by many IDs) must chunk the input to
stay under this limit.

Use the existing utility `trustify_common::db::chunk::chunked_with` for this:

```rust
use trustify_common::db::chunk::chunked_with;

let results = chunked_with(ids, |chunk| async {
    entity::Entity::find()
        .filter(entity::Column::Id.is_in(chunk))
        .all(&txn)
        .await
}).await?;
```

## Observability

See [docs/design/log_tracing.md](docs/design/log_tracing.md) for the full rationale and log levels.

### `#[instrument]` attribute conventions

Prefer `#[instrument]` on the function over manual `.instrument(info_span!(...))` wrappers.
The attribute captures arguments and return values and avoids double-wrapping when caller
and callee are both instrumented. Use `.instrument(info_span!(...))` only for calls into
external code that lacks its own instrumentation (e.g., SeaORM `load_one`,
`load_many_to_many`, raw `.all()` queries).

```rust
#[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
async fn fetch_base_purls(...) { ... }
```

When all arguments are skipped, use `skip_all` instead of listing each one:

```rust
#[instrument(skip_all, err(level = tracing::Level::INFO))]
```

The default `err` level is `ERROR`, which is reserved for events that potentially disrupt
normal operation (see **Levels** in log_tracing.md). Most service functions should lower
the error level to `INFO`.

### Instrumentation scope

- **Instrument** external work — database, object storage, HTTP, message queues — via
  `#[instrument]` on the function or `.instrument(info_span!(...))` on individual awaits
  when inner helpers lack instrumentation.
- **Do not instrument** trivial in-memory work (simple mapping, formatting, small transforms).
- **One span per operation** — either the outer function or an inner `.instrument` on the
  external call, never both for the same work. Nested spans are fine for distinct external
  steps (e.g., several SeaORM loads in one function).
- **Scope by logic, not visibility** — instrument where external I/O happens, including
  non-`pub` helpers.

```rust
use tracing::{info_span, Instrument};

let vulns = all_statuses
    .load_one(vulnerability::Entity, connection)
    .instrument(info_span!("loading vulnerabilities"))
    .await?;
```

### Logging framework

Use `tracing::` for all new code. `log::*` calls inside an `#[instrument]`-annotated
function do not attach to the tracing span, creating gaps in distributed traces. When
modifying a file that uses `log::`, migrate its `log::` calls to `tracing::` in the same
change.

```rust
tracing::debug!("Processing vulnerability {id}");
```

## Data Ingestion: Creator Pattern

**Convention**: Use the `*Creator` batch pattern for data ingestion; do not use the
deprecated `*Context` per-entity pattern.

### Creator pattern (required for new code)

A `*Creator` struct accumulates entries in memory (via `.add()`), then writes them all in
a single `.create()` call using `INSERT ... ON CONFLICT DO NOTHING` with batch chunking.
This approach is concurrency-safe, avoids N+1 queries, and uses consistent lock ordering
to prevent deadlocks.

Key characteristics:
- **Batch-oriented** — collects entries in a deduplicating collection, then inserts in bulk
- **Consuming** — `.create(self, ...)` takes ownership; the creator is single-use
- **Deduplication** — entries are keyed by deterministic UUID or natural key before insert
- **Atomic** — uses `ON CONFLICT DO NOTHING` so concurrent transactions cannot conflict
- **Lock-safe** — sorted/chunked inserts where lock ordering matters (e.g.,
  `OrganizationCreator` sorts by name; others rely on `BTreeMap` key order or the batch
  helper's own ordering)

```rust
// Approved: Creator pattern — batch accumulation then bulk insert
let mut purl_creator = PurlCreator::new();
for purl in &purls {
    purl_creator.add(purl.clone());
}
purl_creator.create(&connection).await?;
```

Examples include `PurlCreator`, `PurlStatusCreator`, `OrganizationCreator`,
`VulnerabilityCreator`, `PackageCreator`, `RelationshipCreator`, `LicenseCreator`,
`CpeCreator`, and `ScoreCreator` — see `modules/ingestor/src/graph/**/creator.rs` for the
full set. When adding ingestion for a new entity type, follow this pattern.

Use creators for batch ingest; use the
[Shared Table Insert Pattern](#shared-table-insert-pattern-duplicate-key-handling) when you
need the existing row ID back on conflict (e.g., `create_doc`).

### Context pattern (deprecated)

The `*Context` structs (e.g., `ProductContext`, `OrganizationContext`) wrap a single loaded
entity model with a reference to the parent `Graph` and perform immediate per-entity
database operations via methods like `ingest_*()`. This design causes:

- **N+1 queries** — each method call triggers individual DB round-trips inside loops
- **Race conditions** — SELECT-then-INSERT is not atomic; concurrent ingestion of the same
  entity causes unique-constraint violations
- **Mixed responsibility** — combines entity representation with ingestion logic

Remaining `*Context` usage is tech debt. Do not extend or add new `*Context` structs. Not
every entity has a `*Creator` yet, so when modifying code that uses a `*Context`, prefer
migrating it to the corresponding `*Creator` in the same change when practical — creating
a new `*Creator` if needed.

```rust
// Avoid: Context pattern — per-entity immediate insert
let org_ctx = graph.ingest_organization(name, info, &connection).await?;
let product_ctx = org_ctx.ingest_product(name, &connection).await?;
```

## Shared Table Insert Pattern (Duplicate Key Handling)

When inserting into a table that has unique constraints and is shared across multiple
modules, use a **nested transaction** to catch duplicate key errors and fall back to
looking up the existing row. This prevents the duplicate key error from aborting the
caller's transaction.

### When to use

Any insert into a table with unique constraints where concurrent or repeated inserts
are expected. The canonical example is the `source_document` table, but the pattern
applies to any shared table with uniqueness guarantees.

### How to implement

1. Wrap the insert in a **nested transaction** (`connection.transaction(...)`) so that
   a constraint violation rolls back only the inner transaction, not the outer one.
2. On success, return the newly created row ID.
3. On error, match `Err(TransactionError::Transaction(DbErr::Query(err)))` and check
   whether the error message contains `"duplicate key value violates unique constraint"`.
4. If it is a duplicate, look up the existing row by its unique column and return it.
5. Propagate any other error normally.

### Reference implementation

The authoritative implementation is `Graph::create_doc` in
`modules/ingestor/src/graph/mod.rs`:

```rust
let result = connection
    .transaction::<_, _, DbErr>(|txn| {
        Box::pin(async move { source_document::Entity::insert(doc_model).exec(txn).await })
    })
    .await;

match result {
    Ok(doc) => Ok(CreateOutcome::Created(doc.last_insert_id)),
    Err(TransactionError::Transaction(DbErr::Query(err)))
        if err
            .to_string()
            .contains("duplicate key value violates unique constraint") =>
    {
        // look up the existing row by unique column and return it
    }
    Err(TransactionError::Transaction(err)) => Err(err.into()),
    Err(TransactionError::Connection(err)) => Err(err.into()),
}
```

### Shared infrastructure: `source_document`

The `source_document` table is shared infrastructure used by multiple modules —
including **ingestor**, **advisory**, **sbom**, and **risk_assessment**. All code paths
that insert into `source_document` must use the nested-transaction duplicate-handling
pattern described above. Failing to do so will cause unhandled constraint violations
under concurrent ingestion.

## Additional Conventions

The anti-patterns below were identified during code review; each entry states the agreed
convention.

### N+1 Query Anti-pattern

**Convention**: Prefer batch loading; allow exceptions when impractical.

Default to batch loading on collection paths — use SQL JOINs, `.is_in()`, or SeaORM
`load_one`/`load_many`. Per-entity DB calls inside loops are permitted only when batching
is impractical or costly; existing N+1 patterns are tech debt to remediate. Loop-based
queries used to stay under PostgreSQL's 65535 bind-parameter limit are not N+1 — see
[Query parameter limits and chunking](#query-parameter-limits-and-chunking).

### Unbounded Queries

**Convention**: Public API list endpoints must be paginated; internal queries may be
unbounded if the caller controls scope.

All public API list endpoints MUST use `PaginatedResults` (see
[Endpoint Patterns](#endpoint-patterns)) and enforce a maximum pagination limit
([ADR-00017](docs/adrs/00017-efficient-pagination.md)). Internal service queries may be
unbounded if the caller controls scope and the table is known to be bounded in practice
(e.g., admin-configured importers).

### In-Memory Filtering Instead of SQL WHERE

**Convention**: Push filters to SQL; filter in Rust only when the rows are already loaded
for another purpose in the same scope.

"The table is small" is not a reason to filter in application code — PostgreSQL's planner
handles small datasets efficiently. Filtering in Rust is acceptable when it eliminates a
duplicate query, i.e. the full result set is already materialized for another purpose.

### Application-Side Counting

**Convention**: Default to SQL `COUNT()`; `.len()` is acceptable if rows are already loaded.

Counts MUST be computed in the database using `COUNT()`, not by materializing rows and
calling `.len()`. Exception: the full collection is already materialized for another
purpose in the same scope. For paginated endpoints, the `total` count is optional and
cached per [ADR-00017](docs/adrs/00017-efficient-pagination.md).

### Missing Batch/Bulk Operations

**Convention**: Use bulk operations for multiple items; single operations for single-item
paths.

Use `insert_many`, `delete_many`, and similar bulk operations when handling multiple
entries. Single-item paths (e.g., `DELETE /resource/{id}`) may use a single `delete_by_id`.

### Recursive Graph Traversal Without Depth Limits

**Convention**: Validate on the way in; error if you cannot handle it.

Validate incoming data (size, shape, depth) before traversal, then treat it as safe to
walk. If something goes wrong during traversal, return an error — never silently skip
parts of the data.

### Missing Database Indexes

**Convention**: Evaluate per-column; record the decision when it is not obvious.

No single rule applies to every column. Weigh the access pattern (filter/sort frequency,
slow queries, public latency, table growth) against the cost (write amplification, storage,
redundancy with existing indexes or UNIQUE constraints). Record the decision in the PR or
migration comment. For migration-side index conventions, see
[Database Indexes](#database-indexes).

### Swallowed Errors

**Convention**: Handle by context.

1. **Instrumentation records the error** — avoid duplicate logging when `err(...)`
   records the returned error. A bare `#[instrument]` or `.instrument(...)` span does
   not record errors automatically; configure error recording or log explicitly.
2. **Return to the caller** — map it; do not also log the same failure redundantly.
3. **Propagate** — if the error stops processing required data, propagate it (`?`,
   `return Err(...)`).
4. **Expected failure** — if failure is normal for this path, ignoring it is fine.
5. **Log before dropping** — if you must drop it, log compactly:
   `.inspect_err(|e| tracing::warn!("…: {e}"))`.

### Stringly-Typed APIs

**Convention**: Use enums for fixed value sets.

Any value drawn from a fixed set (statuses, directions, relationship types) MUST be an
enum, not a `String`. The enum is the single source of truth; string conversion happens
only at serialization boundaries (API input/output, database columns). String matching
against known values is prohibited. Framework-constrained signatures (e.g.,
`Columns::translator` requiring `&str`) are exempt until the framework supports typed
alternatives.

### Code Duplication

**Convention**: Extract shared logic into generics or traits.

When two or more modules implement the same pattern (e.g., label CRUD, license filtering),
extract it into a shared generic function, trait, or macro parameterized by the entity
type. Duplicated logic blocks longer than ~20 lines should be consolidated.

### Oversized Functions

**Convention**: Decompose functions with more than 3 distinct phases.

No hard line limit, but functions with more than 3 distinct phases (identifiable by
blank-line-separated blocks or section comments) should be decomposed. A 150-line
function with a single clear flow is better than five artificial 30-line helpers.

### Public API Documentation

**Convention**: Document all public items.

Every public struct, enum, trait, function, and method MUST have a `///` doc comment. One
line describing what it does is sufficient. Service methods should document parameters,
error conditions, and return-value semantics when non-obvious. Inside functions, add brief
`//` comments only where the logic is not obvious.

### Magic Numbers and Hardcoded Values

**Convention**: Use judgment — prefer named constants when they clarify meaning.

Inline literals in SQL strings (e.g., `relationship = 13`) may stay with a short comment
naming the enum or migration they match, rather than being interpolated with `format!`.
Single-use values stay in the same file unless genuinely reused. Where this file documents
a specific prescriptive pattern (e.g.,
[Shared Table Insert Pattern](#shared-table-insert-pattern-duplicate-key-handling)), that
pattern takes precedence.

### Raw SQL Defeating Parameterization

**Convention**: Allow with review gate.

`Statement::from_string` with dynamic content is allowed but must carry a `// SAFETY:`
comment explaining why parameterization is not possible and confirming that all
interpolated values are validated. Such code requires explicit reviewer approval.

### Database Resource Conventions

These sub-conventions complement [Migration Patterns](#migration-patterns) and
[Entity Model Patterns](#entity-model-patterns).

#### Table and Column Naming

Database object names use `snake_case` (see [Naming Conventions](#naming-conventions)).
Tables use singular nouns (`sbom`, `advisory_vulnerability`). Join tables use
`<left>_<right>` or a domain term. Avoid CamelCase, pluralized table names, and
abbreviated columns (`vulnId`, `Advisories`).

#### Column Types

Use the narrowest correct PostgreSQL type:

| Data | PostgreSQL Type | Rust / SeaORM |
|------|----------------|---------------|
| Primary keys (random) | `UUID` (v7) | `Uuid` with `#[sea_orm(primary_key)]` — v7 has better B-tree locality than v4 |
| Primary keys (content-derived) | `UUID` (v5) | `Uuid` with `#[sea_orm(primary_key)]` — enables upsert patterns by pre-generating the ID |
| Primary keys (domain id) | `VARCHAR` / `TEXT` | `String` with `#[sea_orm(primary_key)]` |
| Foreign keys | Same type as referenced PK | `Uuid` / `String` |
| Timestamps | `TIMESTAMP WITH TIME ZONE` | `OffsetDateTime` / `Option<OffsetDateTime>` |
| Free text | `TEXT` | `String` / `Option<String>` |
| Structured data | `JSONB` | `serde_json::Value` with `#[sea_orm(column_type = "JsonBinary")]` |
| Booleans | `BOOLEAN` | `bool` — use `NOT NULL DEFAULT false`; avoid nullable booleans |
| Scores / metrics | `DOUBLE PRECISION` or `REAL` | `f64` / `f32` |
| Integer values | `INTEGER` | `i32` — for integer-backed enums, importer state, discriminators |
| Fixed value sets | PostgreSQL `ENUM` | `DeriveActiveEnum` (see [Enums](#enums)) |

Avoid `String` for a fixed value set, `TIMESTAMP` without time zone, or `INTEGER` primary
keys without a domain reason.

#### Enums

Store fixed value sets as a typed construct — three patterns, pick the one that fits:

| Pattern | When to use | Example |
|---------|-------------|---------|
| **PostgreSQL ENUM** | Small, rarely-changing string set | `score_type`, `cvss3_severity` |
| **Integer-backed `DeriveActiveEnum`** | Performance-sensitive or Rust-managed sets | `relationship` |
| **Lookup table** | Set that grows over time or carries metadata | `version_scheme`, `status` |

```rust
// PostgreSQL ENUM mapping
#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "score_type")]
pub enum ScoreType {
    #[sea_orm(string_value = "2.0")]
    V2_0,
    #[sea_orm(string_value = "3.1")]
    V3_1,
}

// Integer-backed enum
#[derive(Debug, Copy, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum Relationship {
    #[sea_orm(num_value = 0)]
    Contains,
    #[sea_orm(num_value = 13)]
    Describes,
}
```

Enum type names use `snake_case` (`cvss3_severity`). Variant string values use the domain's
canonical representation (e.g., `"3.1"` for CVSS version).

#### Database Indexes

For idempotency and type guidance, see [Migration Patterns](#migration-patterns). For when
to add an index, see [Missing Database Indexes](#missing-database-indexes).

- **B-tree** is the default for equality and range queries on scalar columns.
- **GIN** for JSONB containment (`@>`), `LIKE`/trigram searches, and array columns.
- **Composite indexes**: create when queries frequently filter on multiple columns
  together; column order follows selectivity (most selective first).
- **Naming (provisional)**: match the dominant pattern in the migration file you are
  editing — `<table>_<col(s)>_idx` or `idx_<table>_<col(s)>`. *(Provisional — replace with
  a single convention once the team decides.)*

#### Foreign Keys and Constraints

- Every column referencing another table MUST have an explicit `FOREIGN KEY` constraint.
- Choose `ON DELETE` deliberately: `CASCADE` when the child lifecycle is tied to the parent
  (e.g., `sbom_node` → `sbom`), `RESTRICT` to prevent deletion while children exist,
  `SET NULL` for nullable optional references.
- Add `UNIQUE` constraints for natural keys or business identifiers
  (e.g., `advisory.identifier`).
- Columns are `NOT NULL` by default; use `NULL` only when absence is a valid domain state.
- `ON UPDATE` is not used — primary keys (`UUID` and domain-natural `String`) are immutable.

```rust
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

#### Migrations

See [Migration Patterns](#migration-patterns) for the core conventions. Additional
conventions:

- **Numbering**: increment by 10 (e.g., `m0002190` → `m0002200`) to leave room for
  insertions.
- **Schema vs. data**: schema migrations registered with `.normal()`; data backfills with
  `.data()`. Prefer no data in schema migrations.

## References

- [Logging and Tracing Design](docs/design/log_tracing.md) — rationale for observability conventions
