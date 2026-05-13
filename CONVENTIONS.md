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

- Endpoints are registered in a `configure()` function that takes `ServiceConfig`, `Database`, and config params
- Services are injected via `web::Data<T>` (Actix application data)
- Authorization uses `Require<Permission>` extractor or `authorizer.require(&user, Permission::...)` call
- Read operations acquire a read transaction: `let tx = db.begin_read().await?;`
- List endpoints accept `Query` (search/filter), `Paginated` (pagination), and return `PaginatedResults<T>`
- Every endpoint has a `#[utoipa::path(...)]` attribute for OpenAPI documentation with `tag`, `operation_id`, `params`, and `responses`
- Route attributes use Actix macros: `#[get("/v3/...")]`, `#[post("/v3/...")]`, `#[delete("/v3/...")]`

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

When a function performs multiple logical steps (e.g., loading data, processing, persisting),
wrap each step with a `tracing::instrument` span to make profiling and debugging easier.
Only use this for calls that lack their own `#[instrument]` attribute:

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
