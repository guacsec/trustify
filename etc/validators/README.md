# Example semantic validators

Ready-to-use configuration and rulesets for the ingestion-time semantic
validators described in ADR 00020. Validation is **disabled by default**;
enabling it is opt-in via a config file.

## Layout

| File | Purpose |
|------|---------|
| `validators.yaml` | The validator set. Referenced by `--validators-config` / `TRUSTD_VALIDATORS_CONFIG`. |
| `rules/csaf-mandatory.json` | CSAF 2.0 required-field checks (JSON ruleset). |
| `rules/spdx-min.json` | SPDX 2.2/2.3 minimum-element checks (JSON ruleset). |
| `rules/cyclonedx-min.json` | CycloneDX minimum checks (JSON ruleset). |

Rulesets use the [`scheck`](https://crates.io/crates/scheck) JSON format
(`.json`).

## Enabling

```bash
trustd api --validators-config etc/validators/validators.yaml
# or
TRUSTD_VALIDATORS_CONFIG=etc/validators/validators.yaml trustd api
```

`rules` paths in `validators.yaml` are resolved relative to the process
working directory. Use absolute paths in production deployments.

To view associated logs set:

```bash
RUST_LOG=trustify_module_ingestor=debug
```

## How it works

Each validator declares:

- `backend.type` — a backend variant with its own settings: `scheck` (assertion-based
  rules), `csaf` (official CSAF spec validator via `csaf-rs`), or `conforma` (a
  remote Conforma CLI server).
- `formats` — which documents it applies to. Concrete formats (`csaf`, `spdx`,
  `cyclonedx`, `osv`, `cve`) or categories (`sbom` = SPDX + CycloneDX,
  `advisory` = CSAF + CVE + OSV).
- `mode` — `report` records findings but never blocks ingestion; `verify`
  rejects a document when a finding is at or above `threshold`.
- `threshold` — lowest severity that gates in `verify` mode (`info` < `warning`
  < `error` < `fatal`); default `error`.
- `on_error` — in `verify` mode, what to do if the validator itself fails to
  run: `block` (treat as a failed gate) or `continue`.
- `backend.phase` — optional scheck phase to activate; omit to run all patterns.
- `backend.profile` — CSAF validation profile / preset. For CSAF
  2.0: `basic`, `extended`, `full`. CSAF 2.1 adds: `mandatory`, `recommended`,
  `informative`, `schema`, `external-request-free`,
  `consistent-revision-history`, `consistent-date-times`, `ssvc`. Defaults to
  `basic`.
- `run_on_ingest` — defaults to `true`; set it to `false` to register a validator
  for explicit invocation from internal code without running it on every ingest.
- `backend.url` — for the `conforma` backend, the base URL of the remote
  `ec validate input --server` instance. The client posts to
  `/v1/validate/input`; `backend.timeout_seconds` defaults to `120`. The server's
  policy is configured when that Conforma server starts; register another
  validator with a different name and URL to select a different policy/server.
  The request body must be JSON or YAML.

Example:

```yaml
validators:
  - name: conforma-pqc
    backend:
      type: conforma
      url: https://conforma.internal.example
      timeout_seconds: 120
    formats: [spdx, cyclonedx]
    run_on_ingest: false
```

Internal code can select the registration by name without ingesting the document:

```rust,ignore
let report = ingestor
    .validate_named("conforma-pqc", &document_bytes, Format::SPDX)
    .await?;
```

The URL is read from the validators configuration; no Conforma-specific
environment variable is required. Use HTTPS or a private, access-controlled
network: the Conforma CLI server does not provide authentication or rate limiting.
Start an instance with its policy mounted/configured before registering its URL, e.g.:

```bash
ec validate input --server --server-address 0.0.0.0 --policy policy.yaml
```

Conforma loads the policy at server startup; restart that instance to apply policy
changes.

In the provided config, `csaf-spec` runs official CSAF specification tests
in `report` mode. `csaf-mandatory` and `cyclonedx-min` run scheck-based
checks in `report` mode (observability only) while `spdx-min` runs in
`verify` mode and will reject non-conforming SPDX documents.

On startup, `trustd` logs the set of engaged validators (name, mode, and
applicable formats), or a note that validation is disabled when none are
configured.
