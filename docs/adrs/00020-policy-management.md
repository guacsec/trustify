# 00018. Policy Management

Date: 2026-06-02

## Status

APPROVED

## Context

Trustify provides SBOM storage, analysis, and vulnerability tracking but lacks automated policy enforcement. Organizations need to validate SBOMs against security and compliance policies (licensing, vulnerabilities, provenance) without relying on manual, inconsistent review processes.

Policy management is the prerequisite step: Trustify must be able to store, retrieve, and manage policy references before any policy validation can be triggered. Policy references identify external policy sources (e.g. git repositories) that a validation engine (such as Conforma) fetches at runtime — Trustify does not store the policy content itself.

This ADR covers policy management (CRUD) which provides the building block for future integration with the Conforma validation engine.

### Requirements

Users need the ability to:

1. Define and manage multiple policy configurations
2. Associate policies with validation backends (initially Conforma)

## Decision

Add a `policy` module to Trustify that stores references to external policies and exposes a CRUD API for managing them.

Trustify stores only the identity and location of a policy (id, name, URL/ref, configuration). Policy content is not cached — the validation engine fetches it at runtime from the referenced source.

### The Data Model

**`policy`** — stores references to external policies, not the policies themselves

- `id` (UUID, PK)
- `name` (VARCHAR, unique) — user-friendly label
- `description` (TEXT) — what this policy enforces
- `policy_type` (ENUM) — `'Conforma'`
- `configuration` (JSONB) — Conforma-specific configuration model shown below

**`policy.configuration` JSONB model:**

This JSONB schema describes the configuration for `policy_type = Conforma`. Future validator backends may use a different configuration shape, so the field remains JSONB to allow backend-specific extensions.

| Field                  | Type     | Required        | Description                                                                                                           |
| ---------------------- | -------- | --------------- | --------------------------------------------------------------------------------------------------------------------- |
| `policyRef`            | string   | yes             | Policy source URL, e.g. `"git://[URL]?ref=[BRANCH OR TAG]"`                                                           |
| `auth`                 | object   | no              | Credentials for private repos; encrypted by client before sending to Trustify (never logged or decrypted by Trustify) |
| `auth.type`            | enum     | yes (if `auth`) | `AuthType` enum: `token`, `ssh_key`, or `none`                                                                        |
| `auth.tokenEncrypted` | string   | no              | Encrypted bearer/PAT token (format defined by client); Trustify stores opaque, validation engine decrypts at use time |
| `policyPaths`          | string[] | no              | Sub-paths within the repo to evaluate                                                                                 |
| `exclude`              | string[] | no              | Rule codes to skip during validation                                                                                  |
| `include`              | string[] | no              | If non-empty, only these rule codes are evaluated                                                                     |
| `timeoutSeconds`       | integer  | no              | Per-policy override of the default execution timeout                                                                  |

`policy.configuration` example:

```json
{
  "policyRef": "git://github.com/org/policy-repo?ref=main",
  "auth": {
    "type": "token",
    "tokenEncrypted": "AES-256-GCM:<base64-nonce>:<base64-ciphertext>"
  },
  "policyPaths": ["policy/lib", "policy/release"],
  "exclude": ["hello_world.minimal_packages"],
  "include": [],
  "timeoutSeconds": 300
}
```

#### Data Model Implementation

```rust
/// The policy reference information
#[derive(Serialize, Deserialize)]
struct Policy {
    id: String,
    name: String,
    description: String,
    configuration: PolicyConfiguration,
}
```

```rust
/// Authentication method for private policy repos
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthType {
    Token,
    SshKey,
    None,
}

/// Credentials for private policy repos (`policy.configuration.auth`)
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyAuth {
    r#type: AuthType,
    token_encrypted: String,
}
```

```rust
/// Policy configuration (stored as JSONB)
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfiguration {
    #[serde(flatten)]
    pub common: CommonImporter,

    /// Reference to the policy source, e.g. git://github.com/org/policy-repo?ref=main
    pub policy_ref: String,

    /// Credentials for private policy repositories
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<PolicyAuth>,

    /// Sub-paths within the policy repository to evaluate
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_paths: Vec<String>,

    /// Rule codes to skip during validation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,

    /// If non-empty, only these rule codes are evaluated
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Per-policy override of the default execution timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
}
```

```rust
/// extending modules/importer/src/model/mod.rs
pub enum ImporterConfiguration {
    // existing code
    Policy(PolicyConfiguration),
}
```

## Consequences

### Policy Management

Trustify stores only external references and does not cache policy content. When `policy.policy_type` is "Conforma", the validation engine fetches the policy at validation time from the git source specified in `policy.configuration.policyRef`.

The trade-off:

- Validation always uses the latest policy content from the referenced branch or tag, but network failures or policy repo outages will cause execution errors.
- Authentication credentials (in `auth.tokenEncrypted`) are stored as opaque encrypted strings. The client encrypts credentials before sending to Trustify; Trustify never decrypts or accesses the encryption key. When the validation engine requests credentials from Trustify, it receives the encrypted blob and is responsible for decryption. This pass-through model keeps Trustify decoupled from the encryption/authentication scheme and eliminates the need for Trustify to manage encryption keys.

### Type Safety

The `configuration` field uses a strongly-typed `PolicyConfiguration` struct rather than raw `serde_json::Value`. Importer:

- Compile-time validation of required fields (`policyRef`)
- Type safety for nested structures (e.g., `AuthType` enum)
- Clear API contract in generated OpenAPI schemas
- Prevention of malformed configurations at ingestion time

The database still stores this as JSONB, but the API layer enforces the typed schema. If future validator backends require backend-specific fields not present in `PolicyConfiguration`, the type can be extended with an optional `extensions: Option<serde_json::Value>` field rather than weakeniImporter type.

### UPDATE and DELETE Semantics and Optimistic Concurrency

**UPDATE (PUT) Semantics:**

- **Without `IfMatch`**: Unconditional update — always succeeds if resource exists and returns `204`
- **With `IfMatch`**: Conditional update with optimistic concurrency control
  - `204` if the resource exists and the ETag matches
  - `404` if the resource doesn't exist (cannot validate the precondition)
  - `412` if the resource exists but the ETag doesn't match

**DELETE Semantics:**

- **Without `IfMatch`**: Idempotent delete — returns `204` whether the resource exists or not
- **With `IfMatch`**: Conditional delete with optimistic concurrency control
  - `204` if the resource exists and the ETag matches
  - `404` if the resource doesn't exist (cannot validate the precondition)
  - `412` if the resource exists but the ETag doesn't match

This distinction ensures that:

- Clients using optimistic concurrency (`IfMatch`) receive explicit feedback when a resource has been modified or deleted by another client, rather than silently overwriting or succeeding
- Clients not using `IfMatch` benefit from simple unconditional update semantics (PUT) and idempotent delete semantics (DELETE)

## Trustify API Endpoints

```
POST   /api/v3/policy          # Create a new policy reference
GET    /api/v3/policy          # List policy references
GET    /api/v3/policy/{id}     # Get a single policy reference
PUT    /api/v3/policy/{id}     # Update a policy reference
DELETE /api/v3/policy/{id}     # Delete a policy reference
```

### Permissions

The policy module introduces the following permissions, following the existing Trustify CRUD convention:

| Permission      | Description                |
| --------------- | -------------------------- |
| `create.policy` | Create policy references   |
| `read.policy`   | List/get policy references |
| `update.policy` | Update policy references   |
| `delete.policy` | Delete policy references   |

### POST `/api/v3/policy`

Create a new policy reference.

**Permission required:** `create.policy`

#### Request

| part | name | type     | description |
| ---- | ---- | -------- | ----------- |
| body | -    | `Policy` |             |

#### Response

- 201 - if the policy was successfully created

  ```yaml
  id: <id> # ID of the created policy
  ```

  And:

  ```
  Location: /api/v3/policy/<id>
  ```

- 400 - if the request could not be understood
- 401 - if the user was not authenticated
- 403 - if the user was authenticated but not authorized
- 409 - if a policy with the same name already exists

### GET `/api/v3/policy`

List policy references, optionally filtered.

By default, the entries will be sorted by name ascending.

**Permission required:** `read.policy`

#### Request

| part  | name     | type       | description                                                    |
| ----- | -------- | ---------- | -------------------------------------------------------------- |
| query | `q`      | "q" string | "q style" query string                                         |
| query | `limit`  | u64        | Maximum number of items to return                              |
| query | `offset` | u64        | Initial items to skip before actually returning results        |
| query | `total`  | bool       | Whether to compute and return the total count (default: false) |

The following `q` parameters are supported:

- `name`: Filters policies by their name.

#### Response

- 200 - if the user is allowed to read policies

  ```rust
  #[derive(Serialize, Deserialize)]
  struct PaginatedResults<Policy> {
      items: Vec<Policy>,
      total: Option<u64>,
  }
  ```

- 401 - if the user was not authenticated
- 403 - if the user was authenticated but not authorized

### GET `/api/v3/policy/{id}`

Get a single policy reference by ID.

**Permission required:** `read.policy`

#### Request

| part | name | type     | description             |
| ---- | ---- | -------- | ----------------------- |
| path | `id` | `String` | ID of the policy to get |

#### Response

- 200 - if the policy was found

  | part    | name   | type     | description                        |
  | ------- | ------ | -------- | ---------------------------------- |
  | body    | -      | `Policy` | The policy information             |
  | headers | `ETag` | string   | Value which indicates the revision |

- 401 - if the user was not authenticated
- 403 - if the user was authenticated but not authorized
- 404 - if the policy id doesn't match a policy UUID record or the user doesn't have permission to read this policy

### PUT `/api/v3/policy/{id}`

Update an existing policy reference.

**Permission required:** `update.policy`

#### Request

| part   | name      | type             | description                    |
| ------ | --------- | ---------------- | ------------------------------ |
| path   | `id`      | `String`         | ID of the policy to update     |
| header | `IfMatch` | `Option<String>` | ETag value, revision to update |
| body   | -         | `Policy`         | The new content                |

#### Response

- 204 - if the policy was successfully updated
- 400 - if the request could not be understood
- 401 - if the user was not authenticated
- 403 - if the user was authenticated but not authorized
- 404 - if the policy id doesn't match a policy UUID record
- 409 - if a policy with the same name already exists
- 412 - if the `IfMatch` header was present, but its value didn't match the stored revision

### DELETE `/api/v3/policy/{id}`

Delete an existing policy reference.

Deleting a policy will fail if there are validation results referencing it.

**Permission required:** `delete.policy`

#### Request

| part   | name      | type             | description                    |
| ------ | --------- | ---------------- | ------------------------------ |
| path   | `id`      | `String`         | ID of the policy to delete     |
| header | `IfMatch` | `Option<String>` | ETag value, revision to delete |

#### Response

- 204 - if the policy was successfully deleted
- 204 - if the policy was already deleted **and no `IfMatch` header was provided** (idempotent delete)
- 400 - if the request could not be understood
- 401 - if the user was not authenticated
- 403 - if the user was authenticated but not authorized
- 404 - if the policy id doesn't match a policy UUID record **and an `IfMatch` header was provided** (cannot validate precondition on missing resource)
- 409 - if the policy has associated validation results
- 412 - if the `IfMatch` header was present, but its value didn't match the stored revision

## File Structure

```
modules/policy/
├── Cargo.toml
└── src/
    ├── error.rs                # Error types
    ├── lib.rs
    ├── endpoints/
    │   └── mod.rs              # REST endpoints
    ├── model/
    │   ├── mod.rs
    │   └── policy.rs           # Policy API models
    └── service/
        ├── mod.rs
        └── policy_manager.rs   # Policy configuration management
```
