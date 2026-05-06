# 00017. Improve pagination: optional total, caching, limit enforcement

Date: 2026-04-21

## Status

APPROVED

## Context

Every paginated endpoint in the API returns a `PaginatedResults<T>` containing an `items` array
and a `total` count. The `total` is computed by executing a `COUNT(*)` query on the full filtered
result set (via sea-orm's `Paginator::num_items()`) on every single request, even when the client
does not need it.

For large tables (advisories, vulnerabilities, SBOMs), the `COUNT(*)` query can be expensive — it
must scan the entire filtered result set regardless of the `OFFSET`/`LIMIT` applied to the data
query. This cost is paid on every page navigation, even though the total rarely changes between
consecutive page requests from the same user session.

Three changes address this:

1. **Make `total` optional** — allow clients to opt in to the count query only when they need it
   (e.g. a UI that needs to render a page count). Clients that do not need the total (infinite
   scroll, CLI tools fetching the next batch, subsequent page requests where the total is already
   known) skip the count entirely.

2. **Cache the total server-side** — when `total` is requested, cache the count result for a
   configurable duration so that repeated paginated requests with the same filters reuse the
   cached count instead of hitting the database again.

3. **Enforce a maximum pagination limit** — reject requests with a `limit` value exceeding a
   configurable maximum (default 1000) with HTTP 400, preventing clients from requesting
   unbounded result sets that could overwhelm the database.

## Decision

### Optional total via query parameter

A new boolean query parameter `total` is added to the `Paginated` struct:

```rust
pub struct Paginated {
    pub offset: u64,
    pub limit: u64,
    pub total: Option<bool>,  // default: false
}
```

When `total` is absent or `false` (the default), the server skips the `COUNT(*)` query entirely
and returns `total: null` in the response. When `total` is `true`, the count is computed (with
caching, see below) and returned as a number.

The response type changes accordingly:

```rust
pub struct PaginatedResults<R> {
    pub items: Vec<R>,
    pub total: Option<u64>,   // null when total was not requested
}
```

This is a breaking change: clients that previously relied on `total` always being present must now
explicitly request it by passing `total=true`.

#### Example

Default request (no total):

```
GET /api/v3/advisory?offset=0&limit=25
```

```json
{
  "items": [...],
  "total": null
}
```

Request with total:

```
GET /api/v3/advisory?offset=0&limit=25&total=true
```

```json
{
  "items": [...],
  "total": 4217
}
```

### Server-side total caching

When `total=true` is requested, the server caches the `COUNT(*)` result keyed by the combination
of:

* Endpoint path (e.g. `/api/v3/advisory`)
* Normalized filter/search parameters (the `Query` and any additional filter parameters that
  affect the result set)

The cache entry is valid for a configurable TTL, set via CLI argument
(`--pagination-cache-ttl`) or environment variable, defaulting to 60 seconds.
The value uses humantime format (e.g. `60s`, `5m`, `1h`):

```
TRUSTD_PAGINATION_TOTAL_CACHE_TTL=60s
```

When a cached total is available and not expired, the server returns it without executing the
`COUNT(*)` query. The data query (with `OFFSET`/`LIMIT`) is always executed — only the count is
cached.

#### Cache implementation

The cache is implemented using [`moka`](https://github.com/moka-rs/moka), a high-performance
concurrent cache crate built for async Rust. `moka` integrates well with tokio and actix-web: it
supports TTL-based expiration natively, is lock-free for reads, and handles concurrent access
without external synchronization.

The cache key must include all parameters that affect the count — the entity type, all filter
predicates, and search terms — but must exclude `offset` and `limit` since those do not affect
the total. This ensures that navigating between pages of the same filtered result set reuses the
cached total.

#### Cache invalidation

The cache relies on TTL-based expiration only. No explicit invalidation is performed on data
mutations (ingestion, deletion). This is acceptable because:

* The total is a convenience for UI pagination, not a consistency-critical value.
* A briefly stale total (off by a few items) does not cause incorrect behavior — the client
  may see a slightly wrong page count, but the items themselves are always fresh.
* TTL-based expiration keeps the implementation simple and avoids coupling the cache to every
  write path.

Mutation-based invalidation is possible but challenging: because the filter is part of the cache
key, a data change would require either re-evaluating cached filters to determine which entries
are affected, or bulk-invalidating all entries for a given entity type (discarding unaffected
entries). This could be revisited if TTL-based staleness turns out to be problematic in practice.

### Maximum pagination limit

A configurable maximum is enforced on the `limit` query parameter. When a request exceeds it,
the server returns HTTP 400 Bad Request with:

* An `X-Pagination-Max-Limit` response header containing the configured maximum, so clients can
  discover and adapt to the limit programmatically.
* A JSON body using the standard `ErrorInformation` format:

```json
{
  "error": "LimitExceeded",
  "message": "requested pagination limit exceeds the maximum of 1000"
}
```

The maximum is set via CLI argument (`--pagination-max-limit`) or environment variable,
defaulting to 1000. Setting it to 0 disables the limit check entirely:

```
TRUSTD_PAGINATION_MAX_LIMIT=1000
```

### Behavior of limit=0

When `limit=0` is passed, the server returns an empty `items` array without executing the data
query. The `total` is still computed if `total=true` is requested. This is a **breaking change**
from the previous behavior where `limit=0` meant "no limit" and returned all items.

### Changes to the Limiter

The `Limiter` struct and its construction are updated to support the optional total:

```rust
impl<'db, C, S1, S2> Limiter<'db, C, S1, S2> {
    /// Returns the total count, using the cache when available.
    pub async fn total(&self, cache: &TotalCache) -> Result<u64, DbErr> {
        cache.get_or_compute(&self.cache_key, || self.paginator.num_items()).await
    }

    /// Fetches the paginated items.
    pub async fn fetch(self) -> Result<Vec<S1::Item>, DbErr> {
        self.selector.all(self.db).await
    }
}
```

Service methods that build `PaginatedResults` check the `total` parameter and either call
`limiter.total()` (with cache lookup) or skip it and set `total: None`.

## Alternatives considered

### External cache (e.g. Redis)

Instead of an in-process cache, the total could be stored in an external cache such as Redis or
Memcached. This would provide a shared cache across all server instances in a multi-instance
deployment, meaning a count computed by one instance could be reused by another.

**Advantages:**

* Shared cache across instances — better hit rate in multi-instance deployments where different
  instances serve requests from the same user session (e.g. behind a round-robin load balancer).
* Centralized TTL management and potential for explicit invalidation via pub/sub or key deletion
  on data mutations.

**Disadvantages:**

* Adds an external infrastructure dependency. Trustify currently does not require Redis or
  similar services, so this would increase operational complexity for deployments.
* Introduces network round-trip latency for every cache lookup. For a value as cheap as a cached
  integer, the network overhead may negate much of the benefit compared to an in-process lookup.
* Requires handling cache unavailability gracefully — the server must fall back to computing the
  count when the external cache is down, adding error-handling complexity.

**Why not chosen:** The pagination total is a performance optimization for a non-critical value.
An in-process cache with `moka` is simpler to deploy, has zero network overhead, and provides
sufficient benefit for the expected workload. In multi-instance deployments, each instance warms
its own cache independently within the TTL — the worst case is one redundant `COUNT(*)` per
instance per TTL window, which is acceptable. If Trustify later introduces Redis for other
purposes, moving the pagination cache there could be reconsidered as a low-effort follow-up.

## Consequences

* The `PaginatedResults` response type changes `total` from `u64` to `Option<u64>`. This is a
  **breaking change** — existing clients that assume `total` is always a number must be updated
  to either pass `total=true` or handle `null`.
* `limit=0` now returns zero items instead of all items. This is a **breaking change** — clients
  that relied on `limit=0` to fetch everything must be updated to use an explicit limit.
* Requests with a `limit` exceeding the configured maximum (default 1000) are rejected with
  HTTP 400. Clients can read the `X-Pagination-Max-Limit` response header to discover the
  server's maximum.
* Clients that do not need the total (the common case) no longer pay the `COUNT(*)` overhead,
  reducing response latency for large result sets.
* Repeated pagination requests with the same filters within the TTL window avoid redundant
  `COUNT(*)` queries, reducing database load during interactive browsing sessions.
* The cache introduces a brief window (up to TTL) where the reported total may be stale after
  data mutations. This is an acceptable trade-off for pagination UIs.
* The cache is in-process and per-instance via `moka`. In multi-instance deployments, each
  instance maintains its own cache. This is acceptable — the cache is a performance optimization,
  not a consistency mechanism, and independent caches converge within the TTL.
* No external infrastructure (Redis, Memcached) is required.
* The TTL default of 60 seconds balances freshness against query reduction for interactive page
  navigation. It can be tuned via configuration.
