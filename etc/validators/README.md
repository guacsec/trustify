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

- `formats` — which documents it applies to. Concrete formats (`csaf`, `spdx`,
  `cyclonedx`, `osv`, `cve`) or categories (`sbom` = SPDX + CycloneDX,
  `advisory` = CSAF + CVE + OSV).
- `mode` — `report` records findings but never blocks ingestion; `verify`
  rejects a document when a finding is at or above `threshold`.
- `threshold` — lowest severity that gates in `verify` mode (`info` < `warning`
  < `error` < `fatal`); default `error`.
- `on_error` — in `verify` mode, what to do if the validator itself fails to
  run: `block` (treat as a failed gate) or `continue`.
- `phase` — optional scheck phase to activate; omit to run all patterns.

In the provided config, `csaf-mandatory` and `cyclonedx-min` run in `report`
mode (observability only) while `spdx-min` runs in `verify` mode and will
reject non-conforming SPDX documents.

On startup, `trustd` logs the set of engaged validators (name, mode, and
applicable formats), or a note that validation is disabled when none are
configured.
