# 00016. Read-only mode switch

Date: 2026-04-20

## Status

PENDING

## Context

In production environments it is sometimes necessary to put Trustify into a read-only mode — for
example during maintenance windows, database migrations, or when the instance is intentionally
deployed as a read-only replica for querying purposes only. Today there is no first-class mechanism
for this. Operators must either restrict access at the network/load-balancer level or set the
database to read-only, which produces unstructured database-level errors that are difficult for
clients and the UI to interpret.

A dedicated read-only mode allows the application to reject mutating requests early, with a clear
and consistent error response, and lets the UI adapt its presentation (e.g. hiding upload buttons,
disabling importer controls) based on a machine-readable status endpoint.

## Decision

### Environment variable

A new environment variable `TRUSTD_READ_ONLY` controls the mode:

```
TRUSTD_READ_ONLY=true    # read-only mode enabled
TRUSTD_READ_ONLY=false   # default, normal read-write operation
```

The corresponding CLI argument is `--read-only`. The value is read once at startup and stored as a
`bool` in the application state (`web::Data<ReadOnlyState>` or equivalent). Changing the mode
requires restarting the application. In managed deployments the variable is typically set by the
operator or an Ansible playbook as part of the deployment configuration, making it easy to roll
out read-only mode across instances without code changes.

### Middleware guard

An actix-web middleware is added to the middleware stack that inspects incoming requests when
read-only mode is active. Any request with an HTTP method that implies mutation — `POST`, `PUT`,
`PATCH`, `DELETE` — is rejected immediately with:

* **HTTP 503 Service Unavailable**
* Body: `ErrorInformation` with `error: "ReadOnly"` and a human-readable message indicating
  that the instance is in read-only mode.

```json
{
  "error": "ReadOnly",
  "message": "This instance is in read-only mode. Mutating operations are not available."
}
```

503 is chosen over 403 because the restriction is operational, not authorization-based — the
caller has permission, but the service is temporarily not accepting writes. `Retry-After` may
optionally be set if a maintenance window duration is known.

`GET`, `HEAD`, and `OPTIONS` requests pass through unaffected.

The middleware is inserted early in the stack (after authentication/authorization) so that
permission checks still run and audit logging still captures the rejected request.

### Importer suspension

When read-only mode is active, the importer server loop skips all execution. The loop itself
continues to run (so the process remains alive and healthy), but no importer runs are started.
This is checked once per tick of the importer loop, using the same shared read-only flag. Importers
retain their configured enabled/disabled state — when the instance returns to read-write mode (by
restarting without the flag), importers that were enabled resume their normal schedule.

### Status endpoint

The existing `GET /.well-known/trustify` endpoint is extended with a `read_only` field:

```json
{
  "version": "0.5.0-beta.1",
  "readOnly": true
}
```

The `readOnly` field is always present (not conditional on authentication) so that the UI can
query it before the user has logged in and adapt accordingly. The `build` field remains gated
behind a valid token as before.

This avoids introducing a separate endpoint and keeps all instance metadata in one place. The UI
can query this endpoint on startup and cache the result for the session lifetime, since the value
cannot change without a restart.

### What is NOT blocked

The following requests are explicitly allowed even in read-only mode:

* All `GET` / `HEAD` / `OPTIONS` requests (queries, searches, downloads, OpenAPI spec).
* Authentication and token validation flows.
* Health and readiness probes on the infrastructure endpoint.

### Scope of the guard

The middleware applies uniformly to all API routes. There is no per-endpoint opt-out. This keeps
the implementation simple and auditable — operators can be confident that read-only mode means no
writes, without having to reason about exceptions.

## Consequences

* A new environment variable `TRUSTD_READ_ONLY` (and CLI flag `--read-only`) is added. It defaults
  to `false`, so existing deployments are unaffected.
* Mutating API requests return 503 with a structured `ErrorInformation` body when the flag is set.
  Clients and the UI can detect the `"ReadOnly"` error code and present appropriate messaging.
* The `/.well-known/trustify` response gains a `readOnly: bool` field. Existing clients that
  ignore unknown fields are unaffected.
* Importers are suspended but not disabled — their persisted configuration is untouched, and they
  resume automatically on restart without the flag.
* The mode is static for the lifetime of the process. Dynamic toggling via an admin API is
  explicitly out of scope for this ADR. Such an endpoint would itself be a mutating operation
  (changing server state via `POST` or `PUT`), which the read-only middleware would reject — making
  it impossible to toggle the mode back on without first disabling the very guard it controls. An
  escape hatch for that single endpoint would undermine the guarantee that read-only mode blocks
  all writes. A restart-based approach avoids this contradiction entirely.
