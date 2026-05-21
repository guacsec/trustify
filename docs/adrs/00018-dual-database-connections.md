# 00018. Dual database connections (R/W + R/O)

Date: 2026-05-08

## Status

APPROVED

## Context

Trustify uses a single `db::Database` struct — a thin wrapper around SeaORM's `DatabaseConnection` — for
all database operations. Every module receives the same connection via `configure()` functions in the
server startup path. This means every query, whether it is an expensive full-text search or a small
metadata write, competes for connections from the same pool against the same PostgreSQL instance.

As the number of Trustify pods scales, all instances share the same database primary. A single PostgreSQL
instance becomes the bottleneck — not because writes are heavy, but because read traffic (searches, SBOM
lookups, vulnerability queries, analysis) vastly outweighs write traffic (ingestion, imports) and
saturates the connection pool. Adding more pods only increases contention on the same database.

PostgreSQL supports streaming replication with read replicas that can serve read-only queries
independently of the primary. Routing read traffic to replicas allows horizontal scaling of the database
layer alongside the application layer. However, PostgreSQL itself does not route queries — the
application must decide which connection to use. This requires application-level database routing: the
ability to maintain two separate connections and direct each query to the appropriate target.

ADR 00016 introduced a read-only mode flag (`--read-only` / `TRUSTD_READ_ONLY`) that gates mutating HTTP
requests at the middleware level. That decision addressed the application-level request routing but did not
address the database connection topology. This ADR builds on that foundation.

## Decision

### Newtype wrappers with actix extraction

Two newtype wrappers are introduced in `common::db`:

```rust
/// Connection to the read-write primary. Full SeaORM capabilities.
pub struct ReadWrite(Database);

/// Connection to a read-only replica (or the primary in fallback mode).
/// Implements ConnectionTrait by delegation. Its TransactionTrait
/// implementation always opens BEGIN TRANSACTION READ ONLY.
pub struct ReadOnly(Database);
```

Both types implement SeaORM's `ConnectionTrait` by delegating to the inner `Database`. The key difference
is the `TransactionTrait` implementation:

* `ReadWrite` opens regular read-write transactions (current behavior).
* `ReadOnly` always opens transactions with `BEGIN TRANSACTION READ ONLY`. PostgreSQL rejects any
  INSERT, UPDATE, or DELETE within a read-only transaction, and a read-only transaction cannot be
  escalated to read-write once started. This provides hard enforcement at the database protocol level.

Both types are registered as `web::Data<ReadWrite>` and `web::Data<ReadOnly>` in the actix application
state. Endpoint handlers declare which connection they need by extracting the appropriate type:

```rust
async fn list_advisories(
    db: web::Data<ReadOnly>,
    // ...
) -> Result<impl Responder, Error> {
    // db is guaranteed to be a read-only connection
}

async fn ingest_sbom(
    db: web::Data<ReadWrite>,
    // ...
) -> Result<impl Responder, Error> {
    // db is a full read-write connection
}
```

This makes the intent explicit in the handler signature and lets the Rust compiler and actix's extractor
system verify that the required connection type is available at startup. No runtime routing, middleware
introspection, or HTTP-method-based switching is needed.

### Read-only transaction enforcement

The `ReadOnly` wrapper's `TransactionTrait` implementation always creates read-only transactions. This
enforcement works regardless of the underlying connection target:

* **Single database (fallback):** Both `ReadWrite` and `ReadOnly` point at the same PostgreSQL instance.
  Writes through `ReadOnly` still fail because the read-only transaction rejects them.
* **Primary + replica:** `ReadOnly` points at a streaming replica. Writes fail both because of the
  read-only transaction and because the replica itself rejects writes. Defense in depth.

This means that even in development or simple deployments with a single database, code that should only
read cannot accidentally write — the read-only transaction prevents it.

### Configuration

A new set of CLI arguments and environment variables is added for the read-only connection, mirroring
the existing `--db-*` / `TRUSTD_DB_*` parameters:

| Purpose | R/W (existing) | R/O (new) |
|---------|---------------|-----------|
| URL | `--db-url` / `TRUSTD_DB_URL` | `--db-ro-url` / `TRUSTD_DB_RO_URL` |
| Host | `--db-host` / `TRUSTD_DB_HOST` | `--db-ro-host` / `TRUSTD_DB_RO_HOST` |
| Port | `--db-port` / `TRUSTD_DB_PORT` | `--db-ro-port` / `TRUSTD_DB_RO_PORT` |
| User | `--db-user` / `TRUSTD_DB_USER` | `--db-ro-user` / `TRUSTD_DB_RO_USER` |
| Password | `--db-password` / `TRUSTD_DB_PASSWORD` | `--db-ro-password` / `TRUSTD_DB_RO_PASSWORD` |
| Name | `--db-name` / `TRUSTD_DB_NAME` | `--db-ro-name` / `TRUSTD_DB_RO_NAME` |
| Max connections | `--db-max-conn` / `TRUSTD_DB_MAX_CONN` | `--db-ro-max-conn` / `TRUSTD_DB_RO_MAX_CONN` |
| Min connections | `--db-min-conn` / `TRUSTD_DB_MIN_CONN` | `--db-ro-min-conn` / `TRUSTD_DB_RO_MIN_CONN` |
| SSL mode | `--db-sslmode` / `TRUSTD_DB_SSLMODE` | `--db-ro-sslmode` / `TRUSTD_DB_RO_SSLMODE` |

The R/O connection pool has its own independent pool sizing. In a read-heavy deployment, operators may
want a larger R/O pool than the R/W pool.

In `common::config`, this is represented as an optional second `Database` struct:

```rust
/// Read-only database options. If not set, the R/W connection is used for reads.
#[command(flatten)]
pub database_ro: Option<DatabaseReadOnly>,
```

### Fallback behavior

All R/O parameters are optional. When none are provided, the `ReadOnly` wrapper is constructed from a
clone of the R/W `Database` connection. This ensures full backward compatibility — existing deployments
with a single database work without any configuration changes.

The read-only transaction enforcement still applies in fallback mode, so the safety guarantee is
maintained regardless of deployment topology.

### Composition with read-only mode (ADR 00016)

The two features compose naturally. The R/W connection (`--db-*`) is always required; the R/O
connection (`--db-ro-*`) can be omitted, in which case it falls back to the R/W connection:

| Scenario | `--db-*` (R/W) | `--db-ro-*` (R/O) | `--read-only` | Effect |
|---|---|---|---|---|
| Single DB, full mode | Primary | *(omit)* | `false` | R/O falls back to primary |
| Single DB, read-only | Primary | *(omit)* | `true` | R/O falls back to primary; writes rejected by middleware |
| Primary + replica, full mode | Primary | Replica | `false` | Reads go to replica, writes to primary |
| Primary + replica, read-only | Primary | Replica | `true` | Reads from replica; writes rejected by middleware |

When `--read-only` is active (ADR 00016), mutating HTTP requests are rejected by middleware before they
reach any handler. The R/W connection is still configured and available, but no write operations will be
performed because the middleware prevents mutating requests from reaching any handler.

### Migrations

Database migrations only run against the R/W connection. Read-only replicas receive schema changes
through PostgreSQL's streaming replication. The migration tooling (`trustd db migrate`) uses the
existing `--db-*` parameters and is unaffected by this change.

### Service-level changes

Each module's `configure()` function signature changes to accept the connection type it needs:

* **Read-only modules** (fundamental queries, analysis, user preferences reads) receive `ReadOnly`.
* **Read-write modules** (ingestor, importer) receive `ReadWrite`.
* **Mixed modules** (e.g. fundamental, which has both query and mutation endpoints) receive both.

The `server/src/profile/api.rs` `configure()` function constructs both wrapper types and passes them
to each module accordingly.

## Alternatives considered

### Middleware-based routing by HTTP method

All GET/HEAD requests automatically use the R/O connection; POST/PUT/PATCH/DELETE use R/W. This avoids
changing handler signatures but has drawbacks:

* Some GET endpoints may need read-after-write consistency (e.g. a GET immediately after an ingest).
  These would silently read stale data from a replica.
* No compile-time visibility into which connection a handler uses.
* Couples connection routing to HTTP semantics rather than business logic.

**Why not chosen:** The type-based approach is more explicit, catches misuse at compile time via actix's
extractor system, and allows handlers to opt into the correct connection based on their actual data access
pattern rather than HTTP method conventions.

### Single connection with read-only transaction wrapper

Instead of two separate connection pools, use a single pool and wrap read-only operations in read-only
transactions. This avoids the configuration complexity of a second connection.

**Why not chosen:** The primary motivation is offloading read traffic to replicas, which requires a
separate connection pointing at a different host. A single pool cannot target multiple PostgreSQL
instances. The read-only transaction is used as an enforcement mechanism, not as a routing mechanism.

### Connection routing inside the Database struct

Add a `Database::read()` / `Database::write()` method that returns the appropriate inner connection.
Callers must remember to call the right method.

**Why not chosen:** This pushes the routing decision into every call site as a runtime choice, with no
compile-time enforcement. Forgetting to call `.read()` would silently use the wrong connection. The
newtype approach makes the choice visible in the function signature and leverages actix's dependency
injection to verify availability at startup.

## Consequences

* Two new types `ReadWrite` and `ReadOnly` are added to `common::db`. Both implement `ConnectionTrait`.
  `ReadOnly`'s `TransactionTrait` always opens read-only transactions, preventing accidental writes even
  in single-database deployments.
* A new set of `--db-ro-*` / `TRUSTD_DB_RO_*` configuration parameters is added. All are optional —
  existing deployments are unaffected.
* Module `configure()` function signatures change to accept `ReadOnly`, `ReadWrite`, or both instead of
  the current `Database`. This is an internal API change; the public HTTP API is unaffected.
* Endpoint handlers are updated to extract `web::Data<ReadOnly>` or `web::Data<ReadWrite>`. This makes
  the data access pattern of each handler self-documenting.
* When `--read-only` is active (ADR 00016), the R/W connection can be omitted. The two features compose
  without conflict.
* Operators can independently size the R/W and R/O connection pools. Read-heavy deployments benefit from
  a larger R/O pool backed by multiple replicas.
* Migrations remain on the R/W connection only. No changes to migration tooling.
