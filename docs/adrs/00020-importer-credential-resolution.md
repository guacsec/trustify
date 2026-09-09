# 00020. Unified importer credential resolution

Date: 2026-08-24

## Status

APPROVED

## Context

Trustify importers fetch data from external sources that may require authentication. Today, each
importer implements its own credential handling:

* **Quay importer:** `api_token: Option<String>` — a bearer token stored as plaintext in the
  importer's `configuration` JSONB column. Uses both an HTTP client (registry API) and an OCI
  client (manifest/blob pulls), each with independent auth.
* **HTTP-based importers** (NVD, CWE, ClearlyDefined, CSAF, SBOM): use `reqwest` or
  walker-based HTTP clients with no shared auth model — each builds its own client.
* **Git-based importers** (OSV, CVE, ClearlyDefined Curation): credential callback in the
  git2 walker, no explicit auth model in the importer configuration.

### Problems

1. **Credentials stored in plaintext in the database.** The `importer.configuration` column is a
   JSONB field that stores the full importer configuration, including secrets. Anyone with database
   read access can extract credentials. This is acceptable for development but not for production.

2. **No shared auth model.** Each importer defines its own auth types and client-building logic.
   Adding a new HTTP-based importer means reimplementing auth from scratch.

3. **No support for external secret stores.** Production deployments typically manage secrets via
   Kubernetes Secrets (populated by Vault, External Secrets Operator, or similar). There is no way
   to reference an external secret — the only option is to put the literal value in the API request
   that creates the importer.

## Decision

### Unified importer auth model

Introduce a shared authentication model for HTTP-based importers, with a parallel model for
git-based importers (deferred — see below). Both share the same `CredentialSource` abstraction
for secret resolution.

The HTTP auth model supports three methods:

* **Basic** — username and password
* **Bearer** — token
* **API key** — header name and value (e.g., `X-Api-Key`)

Each importer exposes an optional `auth` field using this shared model. When absent, the importer
accesses the source without authentication.

### Credential source abstraction

Instead of storing credential values directly, each credential is wrapped in a source descriptor
that specifies *where* to obtain the actual secret at runtime. Three source types are supported:

| Source | Description | Use case |
|--------|-------------|----------|
| **Inline** | Literal value in the configuration | Development and testing |
| **Env** | Read from an environment variable | K8s `envFrom: secretRef` |
| **File** | Read from a file path | K8s volume-mounted secrets |

The file source reads a single value per file. This maps directly to Kubernetes Secret volume
mounts, where each key in a Secret is projected as a separate file (e.g., `/run/secrets/username`
and `/run/secrets/password`). No multi-key file parsing is needed because K8s handles the
key-to-file mapping natively.

**Security note:** The file source accepts a path from the importer configuration and reads it
at runtime. Creating or updating importers requires authorization (OIDC + permissions), so only
privileged users can configure file paths. In production Kubernetes deployments, the pod
filesystem is constrained by the container runtime — only mounted volumes and the container
image are accessible, limiting the scope of readable files.

Credentials are resolved **at import time**, not at importer creation time. This means:

* The database stores only references (env var name or file path), never the actual secret for
  non-inline sources.
* File-based credentials support rotation without pod restart — the importer reads the current
  file contents on each run.
* Environment variables work naturally with Kubernetes `envFrom: secretRef`.

### Kubernetes deployment pattern

The recommended production pattern uses Kubernetes Secrets as the bridge between a secret store
(Vault, External Secrets Operator, cloud provider KMS) and Trustify:

```
Vault / ESO ──sync──▶ K8s Secret ──mount──▶ Pod env vars or volume files
                                                      │
                                            Credential source resolution
                                                      │
                                              Authenticated HTTP client
```

#### Example: env-based credentials (production)

```json
{
  "source": "https://packages.example.com/content/advisories/",
  "auth": {
    "type": "basic",
    "username": { "source": "env", "name": "IMPORTER_USERNAME" },
    "password": { "source": "env", "name": "IMPORTER_PASSWORD" }
  }
}
```

#### Example: inline credentials (development)

```json
{
  "auth": {
    "type": "bearer",
    "token": { "source": "inline", "value": "my-dev-token" }
  }
}
```

#### Example: file-based credentials (production with mounted secrets)

```json
{
  "auth": {
    "type": "basic",
    "username": { "source": "file", "path": "/run/secrets/importer/username" },
    "password": { "source": "file", "path": "/run/secrets/importer/password" }
  }
}
```

#### Example: API key

```json
{
  "auth": {
    "type": "api_key",
    "header": "X-Api-Key",
    "value": { "source": "env", "name": "NVD_API_KEY" }
  }
}
```

### Shared HTTP client construction

Per-importer client-building logic is replaced by a single shared function that resolves
credentials from their configured source and builds an authenticated HTTP client. All HTTP-based
importers delegate to this function instead of implementing their own auth handling.

For importers that use both HTTP and OCI clients (e.g., Quay), the same `auth` configuration
and credential source resolution can feed both clients. The resolved credentials map naturally
to the OCI client's auth model (`Anonymous`, `Basic`, `Bearer`) since it is structurally
identical. The importer resolves credentials once and applies them to both its HTTP and OCI
clients internally.

### Git transport auth model (deferred)

Git-based importers (OSV, CVE, CWE, SBOM, ClearlyDefined Curation) currently use git2's
credential callback scanning `$HOME/.ssh/` for `id_rsa` or `id_ed25519` key files, with no
explicit auth configuration.

The config model defined here for completeness, but implementation is deferred to a
separate piece of work. The git auth model would support three methods using the same
`CredentialSource` abstraction:

* **Basic** (HTTPS) — username and password or token (e.g., GitHub PAT where username is
  `x-access-token`).
* **SSH key** — private key file with optional passphrase, via file-based credential source.
* **SSH agent** — delegates to the system SSH agent. No credentials stored.

#### Example: SSH key from mounted secret

```json
{
  "osv": {
    "source": "git@github.com:github/advisory-database.git",
    "auth": {
      "type": "ssh_key",
      "private_key": { "source": "file", "path": "/run/secrets/git/id_ed25519" },
      "passphrase": { "source": "env", "name": "GIT_KEY_PASSPHRASE" }
    }
  }
}
```

#### Example: HTTPS with personal access token

```json
{
  "osv": {
    "source": "https://github.com/github/advisory-database.git",
    "auth": {
      "type": "basic",
      "username": { "source": "inline", "value": "x-access-token" },
      "password": { "source": "env", "name": "GITHUB_PAT" }
    }
  }
}
```

When `auth` is absent, current behavior is preserved (scanning `$HOME/.ssh/` for key files).

### Migration

A data migration rewrites existing Quay importer configurations in the
`importer.configuration` JSONB column, replacing the old `api_token` field with the new
`auth` structure (Bearer type, inline credential source). Since migrations run on startup
before the application serves requests, stored configurations are in the new format by the
time the application starts.

The `api_token` field is removed. Clients creating Quay importers via the API must use the
new `auth` field. New importers adopt the shared auth model directly.

## Alternatives considered

### Direct Vault integration

The application calls the Vault API directly to fetch secrets at runtime, using a Vault token
or Kubernetes auth method.

**Why not chosen:** Adds a hard dependency on Vault. The env/file approach is Vault-compatible
(via Vault Agent sidecar or ESO) without coupling Trustify's code to any specific secret store.
Operators already have established patterns for projecting Vault secrets into pods.

### Encrypted credentials in the database

Encrypt credentials before storing them in the JSONB column using a server-side key.

**Why not chosen:** Adds key management complexity (where to store the encryption key, rotation,
etc.). The encrypted value is still in the database — a compromise of the DB and the key
exposes all credentials. The reference-based approach avoids storing secrets in the database
entirely.

### Per-importer auth types with a shared trait

Keep separate per-importer auth types but have them implement a common trait.

**Why not chosen:** The auth types are structurally identical (Basic or Bearer with credential
values). Separate types add boilerplate without semantic value. A single shared model is
simpler and ensures consistency.

## Out of scope

### Mutual TLS (mTLS)

Some HTTP sources may require client certificate authentication at the connection level. This
operates independently from request-level auth (Basic, Bearer, API key) — an importer may need
both mTLS and header auth simultaneously. mTLS configuration would be a separate, composable
field alongside `auth`, using the same `CredentialSource` abstraction for certificate and key
paths:

```json
{
  "auth": {
    "type": "basic",
    "username": { "source": "env", "name": "USER" },
    "password": { "source": "env", "name": "PASS" }
  },
  "tls": {
    "client_cert": { "source": "file", "path": "/run/secrets/cert.pem" },
    "client_key": { "source": "file", "path": "/run/secrets/key.pem" },
    "ca_cert": { "source": "file", "path": "/run/secrets/ca.pem" }
  }
}
```

This can be defined in a separate piece of work. The `CredentialSource` abstraction introduced
by this ADR is designed to support it without architectural changes.


## Consequences

* A shared auth model and credential source abstraction are added to the importer module,
  replacing per-importer auth types.
* A shared authenticated client builder is added, replacing per-importer client-building logic.
* Quay's `api_token` field is removed. A data migration rewrites existing configurations to
  the new `auth` structure. This is a breaking API change for clients that create Quay importers.
* The database no longer stores literal credentials in production when operators use env or
  file credential sources.
* File-based credentials support rotation without pod restart.
* Git importer auth model is defined (see above) but implementation is deferred.
* Adding new auth methods (e.g., OAuth2) means extending the shared model in one place.
* mTLS is out of scope but `CredentialSource` is designed to support it in future work.
