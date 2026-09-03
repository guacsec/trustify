# 00020. Semantic validators on ingestion

Date: 2026-09-03

## Status

DRAFT

## Context

Trustify ingests documents (SBOMs, CSAF/CVE/OSV advisories, and others) via two paths:
the HTTP API (`POST /v3/sbom`, `POST /v3/advisory`, `POST /v3/dataset`) and the importers.
Both paths funnel through a single choke point, `IngestorService::ingest`
(`modules/ingestor/src/service/mod.rs:220`), which detects the document format, stores the
raw bytes, and loads the parsed content into the graph.

Today the only quality signal we surface is the free-form `warnings: Vec<String>` field on
`IngestResult` (`modules/ingestor/src/model.rs:4`), populated by the `Warnings` sink
(`modules/ingestor/src/service/mod.rs:320`). These warnings come from our own parsers and
are structural in nature. We have no mechanism to answer *semantic* questions about a
document:

* Does this CSAF advisory carry a well-formed CVE ID?
* Does every remediation reference a vulnerability that actually exists in the document?
* Does this SBOM contain at least one package with a valid PURL?
* Does a `status: final` advisory also carry a `release_date`?

These are cross-field, cross-reference, cardinality, and conditional constraints that schema
validation cannot express. We want to let operators define **sets of validators** that run
on ingestion, in one of two modes:

* **report** — record findings as data-quality signals; never block ingestion.
* **verify** — a gate; if it fails, ingestion is blocked.

The first validator we intend to integrate is [`scheck`](https://github.com/rh-jfuller/scheck),
a semantic-validation tool that runs assertion-based rules (rules-as-data JSON, JSONPath
predicates, Schematron-style `assert`/`report` duality) against JSON/YAML documents. `scheck`
is available as a Rust crate (`scheck::validate_json`, `check_json`, `validate_all`), a static
CLI binary, and a WASM module. Its report model carries severities `fatal`, `error`,
`warning`, `info`.

The long-term goal is to surface validation results in the UX (particularly for importer
runs). This ADR scopes the first increment to the **API path** and to the **ingest-time
plumbing** that both paths already share, so the importer/UX surfacing can be layered on
later without rework.

### Assumptions

* All ingestion flows through `IngestorService::ingest`; a single hook there covers both API
  and importer paths.
* The raw document bytes and the resolved concrete `Format` are both available at
  `service/mod.rs:232-233`, before blob storage and before graph insertion.
* Validators operate on the raw document (JSON/YAML), not on Trustify's parsed graph model.
* Ingestion is fully `async` (tokio); an in-process validator is a cheap function call.

## Decision

### 1. A `Validator` abstraction, `scheck` as the first in-process backend

Introduce an async `Validator` trait in the ingestor module. The trait takes the raw bytes,
the resolved `Format`, and minimal metadata, and returns a structured `ValidationReport`
(never an ad-hoc string). It is deliberately backend-agnostic:

```rust
#[async_trait]
pub trait Validator: Send + Sync {
    /// Stable identifier used in config, reports, and logs.
    fn name(&self) -> &str;

    /// Which formats this validator applies to.
    fn applies_to(&self, format: Format) -> bool;

    /// Run the validator. Returning Err means the validator could not
    /// produce a verdict (crash, timeout, backend unavailable) — this is
    /// distinct from a report that contains failing findings.
    async fn validate(&self, input: &ValidatorInput<'_>) -> Result<ValidationReport, ValidatorError>;
}
```

The first implementation, `ScheckValidator`, links `scheck` as a **workspace dependency and
runs it in-process**. There is no subprocess spawn and no network call in the ingest hot
path. This keeps the first increment deterministic, cheap, and free of new runtime operational
requirements (no sidecar, no binary-on-PATH assumption).

The trait is shaped so that alternative backends — a subprocess wrapper around the `scheck`
CLI, or an HTTP client to an external validator service — can be added later as additional
`Validator` implementations without changing the ingest hook, the report model, or config.
Those backends are explicitly **not** implemented in this ADR (see Alternatives).

### 2. Report model

`ValidationReport` is a typed, serializable model, not a bag of strings:

```rust
pub struct ValidationReport {
    pub validator: String,           // Validator::name()
    pub findings: Vec<Finding>,
    pub outcome: ValidationOutcome,  // Passed | Failed
}

pub struct Finding {
    pub severity: Severity,          // Fatal | Error | Warning | Info
    pub message: String,
    pub path: Option<String>,        // JSONPath / location in the document
    pub rule: Option<String>,        // rule id / flag
}
```

`scheck`'s severities map 1:1. The mapping from findings to `outcome` is governed by the
validator's configured **blocking threshold** (see §4).

### 3. Single hook point in `IngestorService::ingest`

Validators run inside `IngestorService::ingest`, immediately after format detection and
before graph insertion (`service/mod.rs:232-243`). At that point we have the raw `bytes` and
the concrete `fmt`. Concretely:

1. `DocumentDetector::detect_as(bytes, format)` → concrete `Format` (unchanged).
2. **NEW:** run the configured validators whose `applies_to(fmt)` is true.
3. If any **verify** validator blocks → return an error **before** `storage.store` and before
   `detector.load`. Nothing is persisted (see §6).
4. Otherwise proceed with storage + graph load as today, attaching the reports to the result
   (see §7).

Because this is the shared choke point, both API and importer ingestion get validation for
free. The importer runner already threads warnings into its report
(`modules/importer/src/runner/sbom/storage.rs:93`); the structured reports will flow through
the same return value.

### 4. Modes: `report` vs `verify`, driven by a blocking severity threshold

Each validator is configured with:

* a **mode**: `report` or `verify`;
* for `verify`, a **blocking threshold** severity (default `error`): any finding at or above
  the threshold sets `outcome = Failed` and blocks ingestion.

`report` validators never block regardless of severity — their findings are recorded only.

### 5. Verify failures are fail-closed by default

If a **verify** validator returns `Err(ValidatorError)` — it crashed, timed out, or (for a
future external backend) was unreachable — ingestion is **blocked by default**, exactly as if
the gate had failed. A validator that cannot produce a verdict is not allowed to silently wave
a document through unless `on_error: continue` is explicitly configured as a fail-open
exception. This is configurable per validator via `on_error: block | continue`; the default is
`block`. `report`-mode validator errors are logged and ingestion continues.

Choosing `on_error: continue` is a deliberate trade of the verification guarantee for
availability, and should be reserved for validators where a missing verdict is acceptable.

### 6. Blocked documents are not persisted

When a `verify` validator blocks, ingestion is rejected **before** the raw bytes are written
to blob storage and before any `source_document`/graph rows are created. The API returns the
validation report in a structured error body; nothing enters the system. This keeps the store
free of known-bad documents and avoids partial state. (Auditing rejected documents is a
possible future extension — see Open items.)

### 7. Surfacing results

For this increment, validation reports are returned to the caller via `IngestResult`:

* Extend `IngestResult` (`modules/ingestor/src/model.rs:4`) with
  `validation: Vec<ValidationReport>`.
* Continue to fold human-readable finding messages into the existing `warnings: Vec<String>`
  for backward compatibility with current API consumers.

The API upload handlers (`modules/fundamental/src/sbom/endpoints/mod.rs:710`,
`modules/fundamental/src/advisory/endpoints/mod.rs:219`) already return `IngestResult` as JSON,
so no new endpoint is required. Persisting reports (labels or a dedicated table) and rendering
them in the importer UX are **deferred** to a later increment.

### 8. Configuration and rulesets

Validator definitions live in a **config section**, and ruleset files live **on disk**
(bundled with Trustify and/or mounted via ConfigMap). No database schema changes.

Extend `trustify_module_ingestor::endpoints::Config`
(`modules/ingestor/src/endpoints.rs:30`) with a validators configuration, mirrored on
`ModuleConfig` (`server/src/profile/api.rs:370`) and the CLI `Run` args. Each entry declares:

```toml
[[ingestor.validators]]
name       = "scheck-csaf"
backend    = "scheck"        # selects the in-process scheck impl
formats    = ["csaf"]        # maps to Format variants
rules      = ["rulesets/security/csaf-2.0-mandatory.json"]
phase      = "full"          # scheck phase (optional)
mode       = "report"        # report | verify
threshold  = "error"         # blocking severity for verify
on_error   = "block"         # block | continue (verify only)
```

`IngestorService::new` (`modules/ingestor/src/service/mod.rs:204`) gains a
`Vec<Arc<dyn Validator>>` parameter, constructed from config at server assembly
(`endpoints.rs:22`) and at each importer runner's `IngestorService::new(...)` site. When no
validators are configured, ingestion behaves exactly as today.

### 9. Format applicability

`scheck` validates JSON and YAML. The initial integration therefore applies to JSON/YAML
documents (CSAF, CVE, OSV, SPDX-JSON, CycloneDX-JSON). XML CycloneDX is out of scope for the
first backend; `applies_to` returns false for documents whose wire format the validator
cannot consume, so they pass through unvalidated rather than erroring.

## Consequences

* A new `Validator` trait and `ValidationReport` model are added to the ingestor module.
* `scheck` becomes a workspace dependency (in-process). Its footprint and license (MIT) must
  be recorded in `deny.toml`.
* `IngestResult` gains a `validation` field; existing clients that ignore unknown JSON fields
  are unaffected, and `warnings` continues to carry finding messages.
* `IngestorService::new` gains a validators parameter — every construction site (API assembly
  and all importer runners in `modules/importer/src/runner/*`) must pass it, even if empty.
* Ingestion latency increases by the validator run time; in-process `scheck` on a single
  document is cheap, and validation happens before the (more expensive) graph load.
* With no validators configured, behaviour is unchanged — the feature is opt-in.
* `verify` validators can reject uploads; API consumers and importers must handle a new
  "rejected by validation" error outcome.

## Incremental delivery plan

1. **Plumbing (this ADR):** `Validator` trait, `ValidationReport` model, the ingest hook,
   `IngestResult.validation`, and config wiring — with a no-op/empty validator set so nothing
   changes by default.
2. **scheck backend:** `ScheckValidator` in-process impl + bundled starter rulesets; wire
   `report` mode first (never blocks) to gather signal safely.
3. **verify mode:** enable blocking with fail-closed semantics and the rejected-document
   error path on the API.
4. **Persistence + importer/UX:** store reports (labels or a table) and surface them in the
   importer run views.

## Open items

* [ ] Do we persist validation reports for **successful** ingests (labels vs a dedicated
  table), and with what retention?
* [ ] Should rejected documents be optionally auditable (store blob + report under a
  `rejected` label) as a per-instance toggle, despite the default of persisting nothing?
* [ ] Config format: extend the existing typed `Config` vs a standalone validators config
  file discovered by path. Rulesets are files either way.
* [ ] Timeout/resource bounds for validators (matters more once subprocess/HTTP backends
  exist). `scheck` honours `SCHECK_MAX_FILE_SIZE` for input bounds.
* [ ] How do validator definitions interact with importer-specific configuration (per-importer
  overrides vs a single global set)?
* [ ] Versioning of bundled rulesets and how ruleset changes interact with re-processing
  (ADR 00011).

## Alternatives considered

### Subprocess (scheck CLI)

Shell out to the `scheck` binary (`scheck validate --rules … --format json`) and parse its
JSON output. Decouples validator releases from Trustify's build.

* 👍 Independent versioning; matches how `scheck` ships (static musl binary, RPM).
* 👎 Process-spawn cost on every ingest; requires the binary on PATH / in the image.
* 👎 Sandboxing and resource limiting become our problem.

Deferred: the `Validator` trait is designed to accommodate this as an added backend.

### External HTTP validator service

Call a validator over HTTP (sidecar or shared service).

* 👍 Fully decoupled, independently scalable, language-agnostic validators.
* 👎 Adds a network dependency in the ingest hot path; more moving parts and failure modes.
* 👎 Fail-closed verify semantics turn validator outages into ingestion outages.

Deferred: also expressible as a `Validator` backend later.

### WASM-sandboxed validators

Run validators as WASM modules (scheck has a WASM build).

* 👍 Strong sandboxing with in-process locality; pluggable without native linking.
* 👎 Heavier integration (runtime embedding, host bindings) than justified for the first
  validator, which we already own as a Rust crate.

### No abstraction — call scheck directly

Hard-code a `scheck` call in `ingest`.

* 👍 Least code now.
* 👎 The stated requirement is a *set* of validators from *third parties*; a one-off call
  would have to be torn out to support that. The trait is a small, justified abstraction that
  directly serves the requirement.
