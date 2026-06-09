# Coding Conventions

## Language and Framework

- Rust (edition and MSRV are defined in the workspace `Cargo.toml`)
- Web framework: Actix-web 4
- ORM: SeaORM with `DeriveEntityModel`
- Database: PostgreSQL
- API docs: utoipa (OpenAPI generation)
- Async runtime: Tokio
- Error handling: `thiserror` for enum errors, `anyhow` for ad-hoc contexts
- Serialization: serde (JSON)

## Code Style

- Follow `rustfmt` defaults — run `cargo fmt --check` before committing
- Clippy is enforced with strict flags (see the exact invocation in [Pre-commit Workflow](#pre-commit-workflow))
- `unwrap()` and `expect()` are forbidden in production code; they are allowed in tests (configured in `.clippy.toml`)
- Use `?` operator for error propagation, not `.unwrap()`
- All CI checks are run via `cargo xtask precommit` (see [Pre-commit Workflow](#pre-commit-workflow))

## Naming Conventions

- Structs: PascalCase (`SbomService`, `AdvisoryService`, `SbomSummary`)
- Functions/methods: snake_case (`fetch_sbom_summary`, `fetch_advisories`)
- Modules: snake_case (`sbom_group`, `source_document`)
- Entity models: `Model` struct inside each entity module, table names are snake_case (`sbom`, `advisory`, `sbom_group`)
- Service structs: `<Domain>Service` (e.g., `SbomService`, `AdvisoryService`)
- Endpoint functions: short verbs — `get`, `all`, `delete`, `upload`, `download`, `packages`, `related`
- API routes: `/v3/<resource>` (e.g., `/v3/sbom`, `/v3/advisory/{key}`)
- OpenAPI operation IDs: camelCase (`getSbom`, `listSboms`)
- Test functions: descriptive snake_case (`upload_with_groups`, `filter_packages`, `query_sboms_by_label`)

## File Organization

### Workspace layout

```
Cargo.toml              # workspace root
entity/src/             # SeaORM entity models (one file per table)
migration/src/          # Database migrations (m<number>_<description>.rs)
common/                 # Shared crates: common, common/auth, common/db, common/infrastructure
modules/                # Domain modules: fundamental, analysis, ingestor, importer, storage, ui, user
query/                  # Query framework and derive macro
server/                 # HTTP server assembly
trustd/                 # CLI binary
test-context/           # trustify_test_context crate; `TrustifyContext` with `#[test_context]`
e2e/                    # End-to-end tests (hurl files)
```

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
- AI-assisted commits include `--trailer="Assisted-by: Claude Code"`

## Pre-commit Workflow

Before committing any changes, run:

```sh
cargo xtask precommit
```

This command performs the following steps in order:

1. **Regenerates JSON schemas** (`cargo xtask generate-schemas`) — updates schema files derived from Rust model types
2. **Regenerates `openapi.yaml`** (`cargo xtask openapi`) — rebuilds the OpenAPI spec from `#[utoipa::path(...)]` annotations
3. **Runs clippy** (`cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used`)
4. **Runs `cargo fmt`** — applies standard Rust formatting
5. **Runs `cargo check`** (`--all-targets --all-features`) — verifies the project compiles cleanly

Any files modified by steps 1–2 (e.g., `openapi.yaml`, JSON schema files) must be included in the commit.

## Dependencies

- All dependencies are declared in `[workspace.dependencies]` in the root `Cargo.toml` with pinned versions
- Member crates reference workspace dependencies via `dependency.workspace = true`
- Edition 2024 with resolver 3
- Key crate choices: `actix-web` (HTTP), `sea-orm` (ORM), `utoipa` (OpenAPI), `tokio` (async), `serde` (serialization), `anyhow`/`thiserror` (errors), `clap` (CLI)

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

### Type inference

Omit explicit type annotations when the compiler can infer them. Prefer:

```rust
let input_purls = purls.iter().map(|p| parse(p)).collect::<Vec<_>>();
let base_purl_map = base_purls.into_iter().map(|b| (b.key(), b)).collect::<HashMap<_, _>>();
```

Over:

```rust
let input_purls: Vec<InputPurl> = purls.iter().map(|p| parse(p)).collect();
let base_purl_map: HashMap<PurlKey, BasePurl> = base_purls.into_iter().map(|b| (b.key(), b)).collect();
```

This also applies to SeaORM `.all()` calls (which already return `Vec<Model>`) and `push()` calls
where the collection type is already known.

### Iterator ownership

Prefer consuming the collection (`for item in items`, which calls `IntoIterator`) over
`.iter()` + `.clone()` when the source is no longer needed after iteration. This avoids
unnecessary allocations. When you only need references, use `for item in &items`.

Note: `for item in items` and `for item in items.into_iter()` are equivalent for `Vec`;
prefer the shorter form in `for` loops. Use explicit `.into_iter()` in iterator chains
(e.g., `items.into_iter().map(...).collect()`).

```rust
// Good — consumes the collection, no clones needed
for item in items { ... }

// Good — borrow elements
for item in &items { ... }

// Avoid — borrows then clones each element
for item in items.iter() {
    let owned = item.clone();
}
```

### Zipping parallel collections

When iterating over two collections of the same length in lockstep, use `.zip()` instead of
`.enumerate()` + index access. This is safer (no panic on mismatched sizes) and matches
existing codebase patterns:

```rust
// Good — `zip` accepts `IntoIterator` for the right-hand side
for (a, b) in vec_a.into_iter().zip(vec_b) { ... }

// Avoid
for (i, a) in vec_a.iter().enumerate() {
    let b = &vec_b[i]; // panics if sizes differ
}
```

Reference: `modules/fundamental/src/purl/model/details/purl.rs` uses `.zip()` for parallel iteration.

### Pre-allocating collections

Use `Vec::with_capacity(n)` or `HashMap::with_capacity(n)` when the output size is known or
can be estimated from the input size:

```rust
let mut results = Vec::with_capacity(input.len());
```

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

### Accept iterators instead of slices

When a function only iterates over a collection (no indexing, no `.len()`), accept
`impl IntoIterator<Item = T>` instead of `&[T]`. This avoids forcing callers to
allocate intermediate `Vec`s just to pass a slice:

```rust
// Good — caller can pass an iterator directly
async fn fetch_statuses(
    base_ids: impl IntoIterator<Item = Uuid>,
    connection: &C,
) -> Result<..., Error> { ... }

// Avoid — forces caller to collect into a Vec first
async fn fetch_statuses(
    base_ids: &[Uuid],
    connection: &C,
) -> Result<..., Error> { ... }
```

## Observability

See also: [docs/design/log_tracing.md](docs/design/log_tracing.md) for the full rationale.

### `#[instrument]` attribute conventions

Prefer the `#[instrument]` attribute over manual `.instrument(info_span!(...))` wrappers.
The attribute automatically captures function arguments and return values, and avoids
double-wrapping when both the caller and callee are instrumented:

```rust
// Good — attribute on the function
#[instrument(skip(self, connection), err(level = tracing::Level::INFO))]
async fn fetch_base_purls(...) { ... }

// Avoid — redundant span at the call site when callee already has #[instrument]
let purls = self.fetch_base_purls(input, conn)
    .instrument(info_span!("loading base purls"))  // noise — already instrumented
    .await?;
```

Use `.instrument(info_span!(...))` only for calls to external code that lacks its own
instrumentation (e.g., SeaORM `load_one`, `load_many_to_many`, raw `.all()` queries).

### `skip_all` vs listing individual skips

When all arguments are skipped, use `skip_all` instead of listing each one:

```rust
// Good
#[instrument(skip_all, err(level = tracing::Level::INFO))]

// Avoid
#[instrument(skip(base_ids, vp_ids, connection), err(level = tracing::Level::INFO))]
```

### Error level in `#[instrument]`

The default `err` level is `ERROR`, which is reserved for events that potentially disrupt
normal operation (see the **Levels** section in log_tracing.md). Most service functions should lower the
error level to `INFO`:

```rust
#[instrument(err(level = tracing::Level::INFO))]
```

### Tracing spans on sub-operations

When a function performs multiple external I/O steps (e.g., several DB loads), wrap each
step with a `.instrument(info_span!(...))` span to make profiling and debugging easier.
Only apply this to calls that (a) perform external I/O and (b) lack their own `#[instrument]`
attribute. Do not add `.instrument` at the call site when the **callee** already has
`#[instrument]` (see the example under [`#[instrument]` attribute conventions](#instrument-attribute-conventions)).
Nested spans under an instrumented parent are fine for **distinct** external steps (e.g.,
multiple SeaORM loads in one function). See
[Instrumentation scope](#instrumentation-scope) for full scoping rules.

```rust
use tracing::{info_span, Instrument};

// SeaORM calls — no built-in instrumentation, add spans
let vulns = all_statuses
    .load_one(vulnerability::Entity, connection)
    .instrument(info_span!("loading vulnerabilities"))
    .await?;

let statuses = load_purl_statuses(&base_ids, &txn)
    .instrument(info_span!("loading purl statuses"))
    .await?;
```

This splits up large functions into measurable chunks and makes it easier to identify
performance bottlenecks.

### Instrumentation scope

Scope instrumentation to external work — instrument where it matters, not on every `pub`
method by default.

- **Do instrument** — Logic that calls external systems (database, object storage, HTTP,
  message queues). Use `#[instrument]` on the function, or `.instrument(info_span!(...))` on
  individual awaits when inner helpers lack instrumentation.
- **Do not instrument** — Pure in-memory work that is trivial in context (simple mapping,
  formatting, small transforms).
- **Do not double-wrap** — Pick one span per operation: either the outer function or an
  inner `.instrument` on the external call, not both for the same work.
- **Scope by logic, not visibility** — Apply spans where external I/O happens, including
  non-`pub` helpers, not "every public method regardless of what it does."

### Logging framework

Use `tracing::` for all new code; migrate `log::` when touching a file.

`log::*` calls inside an `#[instrument]`-annotated function do not attach to the tracing
span, creating gaps in distributed traces. All new code MUST use `tracing::` macros. When
modifying a file that uses `log::`, migrate its `log::` calls to `tracing::` in the same
change.

```rust
// Approved
tracing::debug!("Processing vulnerability {id}");

// Avoid in new code
log::debug!("Processing vulnerability {id}");
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

### N+1 Query Anti-pattern

**Convention**: Prefer batch loading; allow exceptions when impractical.

Default to batch loading on collection paths — use SQL JOINs, `.is_in()`, or SeaORM
`load_one`/`load_many` to fetch related data in a single query. Per-entity DB calls inside
loops are permitted only when batching is impractical or costly. Existing N+1 patterns are
tech debt to remediate.

```rust
// Approved: batch load with IN clause
let vulns = advisory_vulnerability::Entity::find()
    .filter(advisory_vulnerability::Column::AdvisoryId.is_in(advisory_ids))
    .all(tx)
    .await?;

// Approved: SeaORM batch loader
let orgs = advisories.load_one(organization::Entity, tx).await?;
```

> **Note**: Loop-based queries for PostgreSQL's 65535 bind-parameter limit are valid
> patterns, not N+1 issues — see
> [Query parameter limits and chunking](#query-parameter-limits-and-chunking).

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

PostgreSQL's query planner handles small datasets efficiently, so "the table is small" is
not a reason to filter in application code. Filtering in Rust is acceptable when doing so
eliminates a duplicate query — i.e., the full result set is already materialized for another
purpose and a second filtered query would be redundant.

```rust
// Preferred: filter in SQL
advisory_vulnerability_score::Entity::find()
    .filter(advisory_vulnerability_score::Column::AdvisoryId.eq(advisory_id))
    .all(tx)
    .await?;

// Acceptable: rows already loaded for another purpose, filter avoids a duplicate query
let all_scores = load_all_scores(tx).await?; // needed elsewhere in this scope
let filtered: Vec<_> = all_scores.iter()
    .filter(|s| s.advisory_id == advisory_id)
    .collect();

// Avoid: fetch-all then filter as the primary access pattern
let all_scores = advisory_vulnerability_score::Entity::find().all(tx).await?;
let filtered: Vec<_> = all_scores.into_iter()
    .filter(|s| s.advisory_id == advisory_id)
    .collect();
```

### Application-Side Counting

**Convention**: Default to SQL `COUNT()`; `.len()` is acceptable if rows are already loaded.

Counts MUST be computed in the database using `COUNT()`, not by materializing rows and
calling `.len()`. Exception: if the full collection is already materialized for another
purpose in the same scope, `.len()` is acceptable to avoid a redundant query. For paginated
endpoints, the `total` count is optional and cached per
[ADR-00017](docs/adrs/00017-efficient-pagination.md).

```rust
// Approved: SQL count
let total = entity::Entity::find()
    .filter(condition)
    .count(tx)
    .await?;

// Avoid (for count-only purposes):
let items = entity::Entity::find().filter(condition).all(tx).await?;
let total = items.len();
```

### Missing Batch/Bulk Operations

**Convention**: Use bulk operations for multiple items; single operations for single-item
paths.

Use `insert_many`, `delete_many`, and similar bulk operations when handling multiple entries
in one operation. When the API or code path handles a single item only (e.g.,
`DELETE /resource/{id}`), a single `delete_by_id` is acceptable.

```rust
// Approved: batch delete
source_document::Entity::delete_many()
    .filter(source_document::Column::Id.is_in(doc_ids))
    .exec(tx)
    .await?;

// Avoid: individual deletes in loop
for doc in &docs {
    source_document::Entity::delete_by_id(doc).exec(tx).await?;
}
```

### Recursive Graph Traversal Without Depth Limits

**Convention**: Validate on the way in; error if you cannot handle it.

When data arrives, confirm it can be processed (size, shape, depth, etc.). After validation,
treat it as safe to walk. If something goes wrong during traversal, return an error — do not
quietly skip parts of the data.

```rust
// Approved: validate input, then traverse; propagate errors
fn ingest_document(doc: &Document) -> Result<(), Error> {
    validate_depth(doc, MAX_DEPTH)?;
    walk_tree(doc.root())
}

fn walk_tree(node: &Node) -> Result<(), Error> {
    process(node)?;
    for child in &node.children {
        walk_tree(child)?;  // errors propagate, never silently skipped
    }
    Ok(())
}
```

### Missing Database Indexes

**Convention**: Evaluate per-column with a pros/cons analysis.

No single rule for every column. Before adding (or skipping) an index, weigh these factors:

| For adding an index | Against adding an index |
|---------------------|-------------------------|
| Column is filtered or sorted often in production | Table is small or query volume is low |
| Slow queries or full scans show up in logs | Writes are heavy; extra indexes slow inserts/updates |
| Public API / user-facing latency matters | Existing indexes already cover the access pattern |
| Table is large and still growing | Index would duplicate a UNIQUE constraint |
| Storage cost justifies the overhead | Index storage overhead is significant on large tables |

Record the decision in the PR or migration comment when it is not obvious. For migration-side
conventions (naming, `IF NOT EXISTS`, index types), see [Database Indexes](#database-indexes).

### Swallowed Errors

**Convention**: Handle by context — no one-size rule.

Choose what to do based on the situation:

1. **Instrumentation wrapper exists** — If tracing/metrics will record the failure, no extra
   logging or handling is required.
2. **Return to the caller** — If the API or UI can surface the error, return or map it. Do
   not also log the same failure redundantly.
3. **Propagate** — If the error stops processing required data, propagate it (`?`,
   `return Err(...)`) — do not swallow it.
4. **Expected failure** — If failure is normal for this path (e.g., optimistic lock miss,
   optional field missing), ignoring it is fine; no log required.
5. **Log before dropping** — If you must drop the error and cannot report it upstream, log
   it compactly (e.g., `.inspect_err(|e| tracing::debug!("…: {e}"))`) rather than a verbose
   `match`.

```rust
// Approved: compact log before discarding
serde_json::from_value::<Report>(report)
    .inspect_err(|e| tracing::warn!("Failed to deserialize report: {e}"))
    .ok()

// Avoid: silent discard
serde_json::from_value(report).ok()
```

### Stringly-Typed APIs

**Convention**: Use enums for fixed value sets.

Any value drawn from a fixed set (statuses, directions, relationship types) MUST be
represented as a Rust enum, not a `String`. The enum is the single source of truth — string
conversion happens only at serialization boundaries (API input/output, database columns).
String matching against known values is prohibited. Exception:
framework-constrained signatures (e.g., `Columns::translator` callback requiring `&str`)
are exempt until the framework supports typed alternatives.

```rust
// Approved: enum with serde
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
enum VexStatus { Affected, Fixed, NotAffected, UnderInvestigation, Recommended }

// Avoid: string matching
match status_string.as_str() {
    "affected" => ...,
    "fixed" => ...,
}
```

### Code Duplication

**Convention**: Extract shared logic into generics or traits.

When two or more modules implement the same logic pattern (e.g., label CRUD, license
filtering), extract it into a shared generic function, trait, or macro parameterized by the
entity type. Duplicated logic blocks longer than ~20 lines should be consolidated.

```rust
// Approved: generic label service
async fn set_labels<E: EntityTrait>(
    entity_id: Uuid,
    labels: Labels,
    connection: &impl ConnectionTrait,
) -> Result<(), Error> { ... }
```

### Oversized Functions

**Convention**: Decompose functions with more than 3 distinct phases.

No hard line limit, but functions with more than 3 distinct phases (identifiable by
blank-line-separated blocks or section comments) should be decomposed. Use judgment — a
150-line function with a single clear flow is better than 5 artificial 30-line helpers.

### Public API Documentation

**Convention**: Document all public items.

Every public struct, enum, trait, function, and method MUST have a `///` doc comment. One
line describing what it does is sufficient. Service methods should document their parameters,
error conditions, and return value semantics when non-obvious. Inside functions, add brief
`//` comments only where the logic is not obvious from the code.

### Magic Numbers and Hardcoded Values

**Convention**: Use judgment — prefer named constants when they clarify meaning.

- **Inline in SQL strings** — e.g., `relationship = 13` in raw SQL: prefer leaving the
  literal in the SQL with a short comment explaining which enum/migration it matches, rather
  than interpolating a `const` with `format!`.
- **Single-use imports** — keep the value in the same file for readability unless it is
  genuinely reused elsewhere.

Where this file documents a specific prescriptive pattern (e.g.,
[Shared Table Insert Pattern](#shared-table-insert-pattern-duplicate-key-handling)), that
documented pattern takes precedence over the general "use judgment" rule.

### Raw SQL Defeating Parameterization

**Convention**: Allow with review gate.

`Statement::from_string` with dynamic content is allowed but must be flagged with a
`// SAFETY:` comment explaining why parameterization is not possible and confirming that all
interpolated values are validated. Such code requires explicit reviewer approval.

```rust
// Approved: static SQL with no dynamic values
Statement::from_string(DbBackend::Postgres, STATIC_QUERY.to_string())

// Approved with review gate: dynamic content with SAFETY comment
// SAFETY: `schema_name` is validated against an allowlist in `validate_schema()`.
// Parameterization is not possible because PostgreSQL does not support bind
// parameters for schema identifiers.
let query = format!("SELECT * FROM {schema_name}.entity WHERE id = $1");
Statement::from_sql_and_values(DbBackend::Postgres, &query, [id.into()])
```

### Database Resource Conventions

The following sub-conventions cover database schema patterns. They complement the existing
[Migration Patterns](#migration-patterns) and
[Entity Model Patterns](#entity-model-patterns) sections.

#### Table and Column Naming

All database object names use `snake_case` — see
[Naming Conventions](#naming-conventions) for the general rule. Tables use singular nouns
(e.g., `sbom`, `advisory_vulnerability`). Join tables use `<left>_<right>` or a domain term.
Avoid CamelCase, pluralized table names, or abbreviated column names (e.g., `vulnId`,
`Advisories`).

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

Avoid using `String` for a column that holds values from a fixed set, using `TIMESTAMP`
without time zone, or using `INTEGER` for a primary key without a domain reason.

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

Enum type names use `snake_case` (e.g., `cvss3_severity`). Variant string values use the
domain's canonical representation (e.g., `"3.1"` for CVSS version).

#### Database Indexes

For idempotency and type guidance, see [Migration Patterns](#migration-patterns)
(`.if_not_exists()`). For when to add an index, see [Missing Database Indexes](#missing-database-indexes).

Additional migration-side conventions:

- **B-tree** is the default for equality and range queries on scalar columns.
- **GIN** for JSONB containment queries (`@>`), `LIKE`/trigram searches, and array columns.
- **Composite indexes**: create when queries frequently filter on multiple columns together;
  column order follows query selectivity (most selective first).
- **Naming (provisional)**: Match the dominant naming pattern in the migration file you're
  editing. The team is deciding between `<table>_<col(s)>_idx` suffix (dominant in early
  migrations) and `idx_<table>_<col(s)>` prefix (dominant in newer migrations).
  _(Provisional — this stopgap must be replaced with a single naming convention once the
  team decides.)_

#### Foreign Keys and Constraints

- Every column referencing another table MUST have an explicit `FOREIGN KEY` constraint.
- Choose `ON DELETE` deliberately: `CASCADE` for child-lifecycle-tied-to-parent (e.g.,
  `sbom_node` → `sbom`), `RESTRICT` for prevent-delete-if-children-exist, `SET NULL` for
  nullable optional references.
- Add `UNIQUE` constraints for natural keys or business identifiers (e.g.,
  `advisory.identifier`).
- Columns are `NOT NULL` by default; use `NULL` only when absence is a valid domain state.
- `ON UPDATE` is not used — primary keys (`UUID` and domain-natural `String`) are immutable.

```rust
// Explicit foreign key with cascade
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

See [Migration Patterns](#migration-patterns) for the core conventions (SeaORM framework,
idempotency guards, raw SQL loading, data migration separation). Additional conventions:

- **Numbering**: increment by 10 (e.g., `m0002190` → `m0002200`) to leave room for
  insertions.
- **Reversibility**: implement both `up()` and `down()`.
- **Schema vs. data**: schema migrations registered with `.normal()`; data backfills
  registered with `.data()`. Prefer no data in schema migrations — separate schema changes
  from data changes.

## References

- [Logging and Tracing Design](docs/design/log_tracing.md) — rationale for observability conventions
