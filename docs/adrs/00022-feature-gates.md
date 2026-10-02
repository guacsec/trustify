# 00022. Feature Gates

Date: 2026-09-17

## Status

APPROVED

## Context

Trustify supports a growing set of optional functionality — document formats (CWE, KEV, exploit
intelligence), importers (CVE, NVD, ClearlyDefined, Quay), analytical functionality (PURL recommendations),
and integrations (Exploit Intelligence service). Each was introduced independently and uses a
different enablement pattern:

| Functionality | Enablement mechanism | Client discovery |
|---|---|---|
| Exploit Intelligence | `EXPLOIT_INTELLIGENCE_URL` (presence-based) | `/.well-known/trustify` → `exploitIntelligence: bool` |
| PURL recommendations | `TRUSTD_RECOMMEND_PATTERNS` (presence-based) | None — endpoint returns 503 when unconfigured |
| Semantic validators | `TRUSTD_VALIDATORS_CONFIG` (presence-based) | None — silently no-ops when absent |
| Embedded OIDC | Cargo feature `garage-door` (compile-time) | None |
| CWE / KEV / CVE / NVD / … importers | Always compiled in; data depends on configured importer | None |

This ad-hoc growth creates several problems:

1. **No discoverability.** The UI and API consumers cannot determine which functionality a given Trustify
   instance supports. A client calling the recommendation endpoint gets a 503 with no prior way to know
   the capability was absent. Importers are always compiled into the binary, but whether data for a given
   format (CWE weaknesses, KEV exploits) is available depends on operator configuration — and there is no
   API to query this.

2. **Binary bloat for large optional subsystems.** Major subsystems that bring in their own dependency
   trees are compiled into every binary even when the deployment will never use them. As Trustify adds
   larger integrations (alternative API layers, AI analysis services), this cost compounds.

3. **Inconsistent gating.** Some functionality gates itself with a presence-based URL check, some with a
   file path, and some are always available in code but produce empty results without the right importer.
   Each one implements its own gating pattern.

4. **No unified surface for operators.** There is no single place where an operator can see "what is this
   instance capable of." They must inspect environment variables, importer configurations, and endpoint
   behavior individually.

## Decision

Gating operates on three tiers, each with a distinct purpose. Each tier uses its own term, so that
it is clear which tier is meant:

| Tier | Term | Resolved | Example |
|---|---|---|---|
| 1 | **feature** (Cargo feature) | compile time | `exploit-intelligence` module crate |
| 2 | **capability** | startup, from configuration | `recommendations` |
| 3 | **variant** | startup, from configuration | the `cwe` importer type, the `spdx` format |

"Feature" is only used in the Cargo sense.

### Tier 1: Conditional compilation (Cargo features)

Large, self-contained subsystems that bring in significant additional dependencies are gated behind Cargo
features. This is reserved for coarse-grained functionality — entire API layers, major integrations, or
subsystems with heavy dependency trees — not for individual importers or small features.

#### When to use

A subsystem should be a Cargo feature when it:

- Adds a substantial dependency tree that is entirely unused without the feature
- Represents a major subsystem that some deployments will never use (e.g., a GraphQL API layer, an
  AI-powered analysis engine, a large external integration)
- Has code that is meaningfully separable — it lives in its own module crate

Individual importers, document formats, and small integrations should *not* be Cargo features. The
granularity is "subsystem," not "importer" — splitting every small piece of functionality into its own Cargo feature
fragments the build and makes the compilation matrix unmanageable.

#### Compilation matrix

Every Cargo feature combination that is expected to work must be tested in CI. This means introducing a
Cargo feature requires adding entries to the CI compilation matrix that cover at minimum:

- Default features (the common case)
- Default features + the new feature
- Default features minus the new feature (if it is in `default`)
- All features enabled

The matrix grows combinatorially with the number of features, which is why this tier is reserved for
coarse-grained subsystems. A proliferation of fine-grained features would make CI prohibitively slow.

#### How to implement

Each feature corresponds to a module crate that is an optional dependency of the `server` crate:

```toml
# server/Cargo.toml
[features]
default = []

graphql = ["dep:trustify-module-graphql"]
exploit-intelligence = ["dep:trustify-module-exploit-intelligence"]
```

In the server code, conditional compilation gates the module registration:

```rust
#[cfg(feature = "exploit-intelligence")]
{
    trustify_module_exploit_intelligence::endpoints::configure(
        svc, db_rw.clone(), db_ro.clone(), ei_service,
    );
}
```

#### Relationship to the existing `garage-door` feature

The `garage-door` feature for the embedded OIDC server is an existing example of this pattern. It
demonstrates the approach: a Cargo feature that conditionally includes a dependency and gates code with
`#[cfg(feature = "...")]`. New Cargo-feature-gated subsystems follow the same pattern.

### Tier 2: Configuration gates (capabilities)

Capabilities are compiled into the binary but require operator-provided configuration to function —
external service URLs, regex patterns, config files — and are gated at runtime. The gate is resolved once
at startup and is immutable for the process lifetime.

The capability gate follows the same marker-type pattern used by `Require<Permission>` in the auth
module. A `capability!` macro defines the capability enum and generates a zero-sized marker struct per
variant that implements a `CapabilityRequirement` trait:

```rust
capability! {
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Capability {
        ExploitIntelligence,
        Recommendations,
        SemanticValidation,
    }
}
```

The macro expands each variant into a marker struct and a `CapabilityRequirement` impl — exactly as
the `permission!` macro does for `Permission` / `Require<Permission>`:

```rust
// Generated by the capability! macro:
pub struct ExploitIntelligence;

impl CapabilityRequirement for ExploitIntelligence {
    fn capability() -> Capability {
        Capability::ExploitIntelligence
    }
}

// ... same for Recommendations, SemanticValidation
```

At startup, each capability is added to an `ActiveCapabilities` set only if its configuration is present and
valid. The set is registered as `web::Data<ActiveCapabilities>`. When a Cargo feature is disabled at compile
time, the corresponding variant is never added — the code that checks the configuration is not compiled
in.

#### Guard extractor

A `RequireCapability<T: CapabilityRequirement>` extractor rejects requests when a capability is not in the
active set. Endpoint handlers declare the requirement in their signature using the marker type:

```rust
#[get("/v3/purl/{key}/recommend")]
async fn recommend(
    _gate: RequireCapability<Recommendations>,
    db: web::Data<ReadOnly>,
) -> Result<impl Responder> {
    // only reached if recommendations are configured
}
```

Because the gate is a type, not a string, a misspelled capability name is a compile error — not a silent
runtime failure.

Disabled capabilities return **422 Unprocessable Entity** with a `CapabilityDisabled` error — the same
status code used for disabled variants (tier 3). Both cases represent a request the server
understands but refuses to process because the referenced capability or variant is not active on this
instance. A 5xx code would incorrectly suggest a transient failure that the client should retry.
Clients should not probe endpoints to find out — they check the `capabilities` array of
`/.well-known/trustify` instead (see [Discovery](#discovery-well-knowntrustify)).

```json
{
  "error": "CapabilityDisabled",
  "message": "The 'recommendations' capability is not configured on this instance."
}
```

#### Inline capability check

Not every capability check fits an extractor. When a capability gate needs to be checked *inside* handler or
service logic — for example, in a code path shared by multiple endpoints, or in conditional branches
within a handler — an inline check is provided:

```rust
impl ActiveCapabilities {
    /// Returns `Ok(())` if the capability is active, or `Err(CapabilityDisabled)` if not.
    pub fn require(&self, capability: Capability) -> Result<(), CapabilityDisabled> {
        if self.contains(&capability) {
            Ok(())
        } else {
            Err(CapabilityDisabled(capability))
        }
    }
}
```

`CapabilityDisabled` implements `ResponseError` to produce the same 422 response as the extractor:

```rust
#[derive(Debug, Display, thiserror::Error)]
#[error("The '{0}' capability is not configured on this instance.")]
pub struct CapabilityDisabled(pub Capability);

impl actix_web::ResponseError for CapabilityDisabled {
    fn status_code(&self) -> StatusCode {
        StatusCode::UNPROCESSABLE_ENTITY
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::UnprocessableEntity().json(ErrorInformation {
            error: "CapabilityDisabled".into(),
            message: self.to_string(),
        })
    }
}
```

Usage in handler or service code:

```rust
async fn analyze(
    capabilities: web::Data<ActiveCapabilities>,
    db: web::Data<ReadOnly>,
) -> Result<impl Responder> {
    capabilities.require(Capability::ExploitIntelligence)?;
    // ... rest of handler
}
```

The `?` operator propagates the `CapabilityDisabled` error, which actix converts into a 422 response via
`ResponseError`. This keeps the check to a single line and produces the same structured error as the
extractor approach.

Both mechanisms — the `RequireCapability<T>` extractor and the `capabilities.require()` inline check — produce
identical responses. Use the extractor when the entire endpoint depends on a single capability. Use the
inline check when the gate is conditional, shared across code paths, or needed inside service logic.

### Tier 3: Variant sets

Some categories have multiple variants that can be independently enabled — for example,
which importers are available, or which document formats are supported. These are exposed as named
sets: each category lists which variants within it are active.

```rust
/// Active variants by category.
pub type Variants = HashMap<String, Vec<String>>;
```

Variant sets reflect the intersection of what is *implemented* (compiled into the binary) and what
is *enabled* (not masked out by operator configuration). A variant appears in the set only when both
conditions are met:

- The code for that variant is compiled in (not excluded by a Cargo feature)
- The variant is not disabled by the operator via environment variables or CLI arguments

The canonical example is importers. The set of *implemented* importer types is known at compile time —
each compiled-in importer type registers itself. By default all implemented types are available. The
operator can narrow this set via configuration (e.g., environment variables or CLI arguments that mask
out specific types). The `variants.importers` array contains the resulting active set.

This means the variant set is resolved at startup from the compiled-in types and the operator's
configuration, following the same lifecycle as tier 2 configuration gates.

Disabled variants are enforced, rejected requests return **422** with a `VariantDisabled` error:

- Ingesting a single document of a disabled format is rejected.
- In a dataset (zip) ingestion, files of a disabled format are skipped and reported in the dataset
  warnings. The rest of the dataset is still loaded.
- Creating, updating, patching, enabling, or force-running an importer of a disabled type is rejected.
  Disabling such an importer is still possible.
- Existing, enabled importers of a disabled type are never scheduled. Their `lastError` is set once
  (using a conditional update, so restarts and multiple instances don't repeat it) and a single warning
  is logged.

The format filter and the importer filter are independent mechanisms. The format filter gates
document uploads and dataset ingestion only — it does not apply to importer-driven ingestion. Importers
are not tied to a single format (e.g., the `sbom` importer handles both SPDX and CycloneDX, and `http`
auto-detects the format), so format-level filtering cannot be meaningfully mapped onto importer types.
To prevent ingestion of a specific format, the operator disables the format via the format filter (which
blocks uploads) and separately disables or does not configure importers that would produce documents in
that format. Read-only parsing endpoints, like `POST /v3/ui/extract-sbom-purls`, are not affected by
either filter.

The `/.well-known/trustify` response exposes the active sets so the UI can adapt its presentation
accordingly.

### Discovery: `/.well-known/trustify`

The well-known endpoint response is extended with `capabilities` and `variants`:

```json
{
  "version": "0.6.0",
  "readOnly": false,
  "capabilities": [
    "exploitIntelligence",
    "recommendations"
  ],
  "variants": {
    "formats": ["csaf", "cve", "cyclonedx", "osv", "spdx"],
    "importers": ["cwe", "kev", "csaf", "sbom", "nvd"]
  },
  "build": { ... }
}
```

**`capabilities`** is a flat array of active capability names. Presence means the capability is compiled in *and*
configured. If a capability is absent, it is either not compiled into the binary or not configured.
Clients check membership: `capabilities.includes("recommendations")`.

**`variants`** is a map of category name → array of active options. Categories are always present;
an empty array means no options are active for that category. Clients check `variants.importers`
to see which importer types are enabled. This reflects the compiled-in types and the operator's filter,
not the importer configurations that currently exist.

The existing top-level `exploitIntelligence` field is preserved for backward compatibility but
deprecated. New capabilities are added exclusively to the `capabilities` array.

`readOnly` remains top-level — it is an operational mode, not a capability.

### How the tiers compose

The three tiers form a layered gate:

```
Cargo feature (compile-time)
  └─ Is the subsystem compiled into the binary?
      └─ Configuration gate (startup-time)
          └─ Is the capability configured on this instance?
              └─ Variant set (enforced per category)
                  └─ Which variants within the category are active?
```

Functionality disabled at any tier is unavailable. A Cargo feature disabled at build time means its
capabilities never appear in `capabilities` and its types never appear in `variants`. A Cargo feature enabled but
not configured at runtime means the capability is absent from `capabilities`. An importer type that is compiled in but
masked out by operator configuration does not appear in `variants.importers` — and importers of that
type configured in the database will not run.

### What is NOT gated

* **Read-only mode** (`--read-only` / `TRUSTD_READ_ONLY`) — an operational mode, not a capability.
* **Configuration limits** (`TRUSTD_SBOM_UPLOAD_LIMIT`, `TRUSTD_MAX_GROUP_NAME_LENGTH`) — tuning
  parameters for always-present functionality.
* **Infrastructure** (database, storage, auth) — prerequisites, not optional functionality.
* **Multi-tenancy and per-user access control.** Gates are instance-wide: a capability is
  either available to all authenticated users or unavailable entirely. Per-tenant or per-user
  restrictions on which capabilities are accessible (e.g., tenant A can use recommendations but tenant B
  cannot) are an access-control concern, not a gating concern, and are out of scope for this ADR.

### Adding a new gate

When introducing new optional functionality:

1. **Is it a large subsystem with significant dependencies?** → Add a Cargo feature in
   `server/Cargo.toml`, gate the module registration with `#[cfg(feature = "...")]`, add the
   necessary CI compilation matrix entries, and decide whether it belongs in `default`.
2. **Does it require operator configuration?** → Add an entry to the `Capability` enum, add it to the active set
   at startup when configured, and guard endpoints with `RequireCapability` or `capabilities.require()`.
3. **Does it have multiple independently-enabled options?** → Add an entry to the `variants` map
   with the active options.

The `/.well-known/trustify` response picks up new capabilities and variants automatically.

### Migration path

Existing functionality is migrated incrementally:

1. **Exploit Intelligence** — already has `ExploitIntelligenceState(bool)` and a top-level
   `exploitIntelligence` field. Migration: add `Capability::ExploitIntelligence` to the active set when the
   URL is configured, deprecate the top-level field, replace `ExploitIntelligenceState` with
   `RequireCapability` or inline `capabilities.require()` calls. Optionally introduce a Cargo feature
   `exploit-intelligence` if the dependency footprint warrants it.

2. **PURL recommendations** — currently returns 503 inline. Migration: add
   `Capability::Recommendations` to the active set when `!recommend_patterns.is_empty()`, replace the
   inline check with `RequireCapability`.

3. **Semantic validators** — currently a silent no-op. Migration: add `Capability::SemanticValidation`
   when `validators_config.is_some()`. No endpoint guard needed (validators run during ingestion), but
   presence in `capabilities` makes the state discoverable.

4. **Importers** — register all compiled-in importer types, apply operator configuration to determine
   the active set, and populate `variants.importers`. Importers that are configured in the database
   but whose type is not in the active variant set are skipped — their `lastError` is set once
   (using a conditional update so that restarts and multiple instances do not repeat it) and a single
   warning is logged; after that they will not run. Creating an importer of a disabled type is rejected
   at the API level.

## Alternatives considered

### Runtime-only gating without conditional compilation

Everything is always compiled in; gating is purely configuration-based at runtime.

**Why not chosen:** For small functionality this is fine — and most functionality will use only runtime gating.
But large subsystems with heavy dependency trees (alternative API layers, AI integrations) should not
be forced into every binary. Conditional compilation provides an escape hatch for these cases, keeping
binary size and build times manageable for operators who do not need those subsystems.

### Cargo features only, no runtime discovery

Use `#[cfg(feature = "...")]` to gate everything and let clients infer availability from endpoint
existence (404 vs. 200).

**Why not chosen:** Clients cannot distinguish "not compiled in" from "endpoint typo" from
"compiled in but not configured." A structured discovery response lets the UI adapt its
presentation without probing individual endpoints. Runtime configuration gates also allow a single
binary to serve different deployment profiles based on environment variables.

### Fine-grained Cargo features per importer

A separate Cargo feature for each importer type (CWE, KEV, CVE, NVD, etc.).

**Why not chosen:** Individual importers share most of their dependency tree (SeaORM, the ingestor
framework, common walker infrastructure). Splitting them into separate Cargo features provides little
binary size reduction while multiplying the CI compilation matrix. The cost of testing every combination
outweighs the benefit. Importers are better handled at tier 2/3 — runtime configuration and variant
sets.

### Boolean maps with explicit `false` entries

Every possible capability appears in the response as `true` or `false`, ensuring clients always have a
complete picture.

**Why not chosen:** Requires the server to enumerate all possible capabilities regardless of compilation —
capabilities excluded by Cargo features would need stub entries. A presence-based model is simpler: if a
capability is absent, it is not available. This also avoids coupling the response schema to the full set
of possible capabilities, which changes across versions.

## Consequences

* A three-tier gating model is established: compile-time (Cargo features for large subsystems),
  configuration-time capabilities (`capabilities` array), and variant sets (`variants` map). Each tier serves a
  distinct purpose and composes with the others.

* Cargo features are reserved for coarse-grained subsystems with significant dependency impact. Each
  new Cargo feature requires corresponding CI compilation matrix entries to test the relevant
  combinations.

* The `/.well-known/trustify` response gains a `capabilities` array (active configuration-gated
  capabilities) and a `variants` map (active variants per category, e.g., importers). Presence in these collections
  means active; absence means unavailable. The existing `exploitIntelligence` top-level field is
  deprecated but preserved.

* Two complementary mechanisms are provided for checking capabilities: a `RequireCapability`
  extractor for endpoint-level guards, and an inline `capabilities.require(Capability::Foo)?` call for checks inside
  handler or service logic. Both produce the same 422 `CapabilityDisabled` error response.

* Variant sets are enforced at the API level — disabled formats are rejected during ingestion and
  disabled importer types cannot be created. The `/.well-known/trustify` response exposes the active
  sets so the UI can adapt its presentation.

* Operators can query a single endpoint to see the full profile of an instance. The UI reads
  `capabilities` and `variants` on startup and conditionally renders controls, replacing per-capability
  detection logic.

* Operators building custom binaries can exclude large subsystems at compile time when the dependency
  footprint warrants it, reducing binary size and build times. The default feature set is
  backwards-compatible — existing builds without explicit feature selection continue to include the
  same functionality.
