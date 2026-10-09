# Example semantic validators

Ready-to-use configuration and rulesets for the ingestion-time semantic
validators described in ADR 00021. Validation is **disabled by default**;
enabling it is opt-in via a config file.

## Layout

| File | Purpose |
|------|---------|
| `validators.yaml` | The validator set and the storage settings. Referenced by `--validators-config` / `TRUSTD_VALIDATORS_CONFIG`. |
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

## Top-level settings

Alongside `validators`, the file carries two settings that apply to all of them:

- `persist_reports` — defaults to `true`. When `false`, nothing is written to
  the `validation_report` table and every result is logged at `debug` instead.
  This overrides the per-validator `persist` setting.
- `caps.max_findings` / `caps.max_findings_bytes` — bound how much of a report
  is stored, defaulting to 200 findings and 64 KiB. Validator output is
  untrusted and unbounded, and a loose ruleset against a large document can
  otherwise produce megabytes per report. A report that hits either limit is
  stored with the surplus findings dropped and `truncated` set, while
  `finding_count` still reports everything the validator found.

## Stored results

Every validator result for a document that is ingested is recorded, in both
`report` and `verify` mode. A document that `verify` **rejects** is recorded
too, with `blocked` set — it never reaches storage, so this row is the only
trace that the instance refused it.

The table is append-only. A validator that runs again against an unchanged
document with an unchanged configuration writes nothing; a row appears only
when the result or the validator configuration differs from the last one
stored. Re-running an importer over documents that have not changed therefore
does not grow the table, and when a ruleset does change, the previous verdict
is still there next to the new one.

Reports are read back through `GET /api/v3/validation`, which is filterable and
paginated, and `GET /api/v3/validation/{key}`, where the key is a digest
(`sha256:<hex>`) or the `urn:uuid:<uuid>` of an ingested SBOM or advisory.
Rejected documents are only reachable by digest, or by filtering the list on
`blocked`. Both endpoints require the `read.validation` permission.

Reports are *not* stored for `validate_named`, the explicit by-name invocation
used by internal callers: that is an ad-hoc query, not an ingestion.

To view the logs instead — which is all you get with `persist_reports: false`
— set:

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
- `persist` — defaults to `true`; set it to `false` to log this validator's
  results instead of storing them.
- `revalidate` — defaults to `always`: a document is validated again even when
  it has been seen before. Set it to `on_change` to skip the run when neither
  the document nor the validator configuration has changed since the stored
   result. Only safe for backends whose verdict depends entirely on inputs we
   can fingerprint, which excludes `conforma`: its policy lives on the remote
   server and can change without any change here, so `on_change` would serve a
   stale verdict. Reports whose stored findings were truncated are revalidated
   to preserve the complete findings in the ingest response.
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

Changing a ruleset file counts as a configuration change: the fingerprint
recorded with each result covers the ruleset contents, not just the path in
`validators.yaml`.

In the provided config, `csaf-spec` runs official CSAF specification tests
in `report` mode. `csaf-mandatory` and `cyclonedx-min` run scheck-based
checks in `report` mode (observability only) while `spdx-min` runs in
`verify` mode and will reject non-conforming SPDX documents.

On startup, `trustd` logs the set of engaged validators (name, mode, and
applicable formats), or a note that validation is disabled when none are
configured.
