# Development Guide

## Rust

If you haven't already, [get started with Rust](https://www.rust-lang.org/learn/get-started).

See [CONVENTIONS.md](../CONVENTIONS.md) for coding standards, linting, and pre-commit workflow.

### macOS: Shared Memory Limits

Concurrent Postgres instances during testing can exhaust shared memory on macOS.
Adjusting shared memory is not straightforward — use
[this guide](https://unix.stackexchange.com/questions/689295/values-from-sysctl-a-dont-match-etc-sysctl-conf-even-after-restart).

## PostgreSQL

Unit tests and "PM mode" use an embedded Postgres instance installed automatically
on the local filesystem. You can also use an external database.

### Starting a containerized instance

```shell
podman-compose -f etc/deploy/compose/compose.yaml up
```

### Connecting via psql

```shell
env PGPASSWORD=trustify psql -U postgres -d trustify -h localhost -p 5432
```

If `psql` is not available locally:

```shell
podman-compose -f etc/deploy/compose/compose.yaml exec postgres psql -U postgres -d trustify
```

### Pointing the app at an external database

```shell
RUST_LOG=info cargo run --bin trustd api --db-password trustify --devmode --auth-disabled
```

Run `cargo run --bin trustd api --help` for all database options.

## Authentication

By default, authentication is enabled. For development, you have two options:

- **Disable auth:** `--auth-disabled` flag or `AUTH_DISABLED=true` env var
- **Dev mode:** `--devmode` uses the Keycloak instance from the compose deployment

For full OIDC setup, see [oidc.md](oidc.md).

### Using bearer tokens

HTTP requests must provide a bearer token via the `Authorization` header.
You can use the `oidc-cli` tool:

```bash
cargo install oidc-cli
```

Set up the client (re-run when Keycloak is re-created):

```bash
oidc create confidential trusty \
  --issuer http://localhost:8090/realms/trustify \
  --client-id walker \
  --client-secret ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS
```

Make authenticated requests:

```bash
curl -H "Authorization: Bearer $(oidc token trusty -b)" \
  http://localhost:8080/purl/asdf/dependencies
```

## Repository Organization

### Sources

| Directory | Purpose |
|-----------|---------|
| `common` | Shared model types used across modules |
| `entity` | Database entity models (SeaORM) |
| `migration` | SeaORM DDL migrations |
| `modules` | Primary application behavior |
| `server` | REST API server |
| `trustd` | Server CLI binary |

### Supporting files

| Directory | Purpose |
|-----------|---------|
| `etc/test-data` | Test data for unit tests |
| `etc/datasets` | Integrated data bundles for demos |
| `etc/deploy` | Deployment files (compose, etc.) |

## Data Loading

### Datasets

Bundled datasets are available in `etc/datasets`:

```shell
cd etc/datasets && make
curl -X POST http://localhost:8080/api/v3/dataset \
  --data-binary @ds1.zip -H "Content-Type: application/zip"
```

### Upload via UI

Use the upload page at http://localhost:8080/upload

### Upload via API

```shell
curl -X POST http://localhost:8080/api/v3/sbom \
  --data-binary @some-sbom.json -H "Content-Type: application/json"
curl -X POST http://localhost:8080/api/v3/advisory \
  --data-binary @some-advisory.json -H "Content-Type: application/json"
```

### Importers

Configure importers to regularly fetch from remote sources.
See [modules/importer/README.md](../modules/importer/README.md).
