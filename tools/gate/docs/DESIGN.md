# Trustify Gate

CI/CD policy gate that evaluates SBOMs against configurable security and
compliance policies using data from a running Trustify instance.

## Purpose

The gate answers: **"Should this build be allowed to ship?"**

It fetches vulnerability, advisory, and license data from Trustify, runs it
through one or more **checker plugins**, and exits non-zero if any policy
violations are found. Designed to run in CI/CD pipelines (GitHub Actions,
GitLab CI, Jenkins, Tekton) as a quality gate before release.

## Architecture

```
                         gate.py (CLI)
                            |
                    +-------+-------+
                    |               |
                client.py      checkers/
                (Trustify API)     |
                    |         +----+----+----+
                    |         |         |    |
                    v      builtin  conforma  ...
               Trustify     checker  checker
               REST API
```

### Plugin system

Policy evaluation is delegated to **checker plugins** in `checkers/`. Each
checker:

1. Implements the `Checker` protocol (a `name` property and a `check()` method)
2. Registers itself via `register_checker()` at import time
3. Receives a `CheckContext` (SBOM data, PURLs, vulnerabilities, advisories,
   licenses) and its own config dict
4. Returns a list of `Violation` objects

The gate config file specifies which checkers to run and their individual
configuration. Multiple checkers run sequentially; all violations are
aggregated.

### Adding a new checker

1. Create `checkers/mychecker.py`
2. Implement a class with `name` property and `check(ctx, config)` method
3. Call `register_checker("mychecker", MyChecker)` at module level
4. Import the module in `checkers/__init__.py`

## Checkers

### `builtin` -- Threshold-based checker

Evaluates Trustify vulnerability analysis and advisory data against
declarative rules. No external tools required.

Config:

```json
{
  "name": "builtin",
  "config": {
    "vulnerabilities": {
      "max_severity": "high",
      "max_score": 9.0,
      "deny": ["CVE-2021-44228"],
      "ignore": ["CVE-2024-9999"],
      "ignore_unfixed": false
    },
    "licenses": {
      "deny": ["GPL-3.0*", "AGPL-*"],
      "allow": ["MIT", "Apache-2.0", "BSD-*"]
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `max_severity` | Fail if any vuln exceeds this level (none/low/medium/high/critical) |
| `max_score` | Fail if any CVSS score exceeds this value |
| `deny` | Always fail on these specific CVE IDs |
| `ignore` | Skip these CVE IDs entirely |
| `ignore_unfixed` | Skip vulns with status not_affected/under_investigation |
| `licenses.deny` | Glob patterns for denied licenses |
| `licenses.allow` | If set, any license NOT matching is a violation |

### `conforma` -- Conforma/Enterprise Contract checker

Validates Trustify data against OPA/Rego policies using the Conforma `ec`
CLI or its HTTP server mode.

The checker assembles a policy input document from Trustify data and passes
it to Conforma. All Trustify data is available under `input.trustify` in
Rego rules.

**CLI mode** (default):

```json
{
  "name": "conforma",
  "config": {
    "mode": "cli",
    "ec_binary": "ec",
    "policy": "git::https://github.com/conforma/policy//policy/release",
    "extra_args": ["--ignore-rekor"]
  }
}
```

**Server mode** (Conforma running as HTTP service):

```json
{
  "name": "conforma",
  "config": {
    "mode": "server",
    "server_url": "http://localhost:8090"
  }
}
```

| Field | Description |
|-------|-------------|
| `mode` | `cli` (subprocess) or `server` (HTTP POST) |
| `ec_binary` | Path to the `ec` binary (default: `ec` on PATH) |
| `policy` | Inline Conforma policy source (git URL, OCI ref, or local path) |
| `policy_file` | Path to an EnterpriseContractPolicy YAML file |
| `server_url` | URL of a running Conforma HTTP server |
| `extra_args` | Additional CLI arguments passed to `ec validate input` |

## SBOM input modes

| Mode | Flag | What happens |
|------|------|--------------|
| Local file (no upload) | `--sbom ./sbom.json` | PURLs extracted locally, analyzed via Trustify API |
| Local file (upload) | `--sbom ./sbom.json --upload` | SBOM uploaded to Trustify, then full analysis |
| By name | `--sbom-name "product-1.0"` | Looks up SBOM in Trustify by name |
| By ID | `--sbom-id urn:uuid:...` | Fetches SBOM from Trustify by UUID |

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| `table` | `--format table` | Human-readable terminal output (default) |
| `json` | `--format json` | Machine-readable, CI/CD artifact storage |
| `sarif` | `--format sarif` | GitHub Code Scanning, IDE integration |
| `junit` | `--format junit` | Jenkins, GitLab CI, any JUnit-compatible system |

## Trustify API endpoints used

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v3/sbom` | Upload SBOM |
| `GET /api/v3/sbom` | Find SBOM by name |
| `GET /api/v3/sbom/{id}` | SBOM detail |
| `GET /api/v3/sbom/{id}/advisory` | Advisories affecting the SBOM |
| `GET /api/v3/sbom/{id}/packages` | Packages in the SBOM |
| `GET /api/v3/sbom/{id}/all-license-ids` | License inventory |
| `POST /api/v3/vulnerability/analyze` | Batch PURL vulnerability analysis |
| `GET /api/v3/vulnerability/{id}` | Vulnerability detail |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTIFY_URL` | `http://localhost:8080` | Trustify server URL |
| `TRUSTIFY_TOKEN` | (empty) | Bearer token for authentication |

## CI/CD integration examples

### GitHub Actions

```yaml
- name: Trustify Gate
  run: |
    cd tools/gate
    uv run python gate.py check \
      --sbom ${{ github.workspace }}/build/sbom.json \
      --upload \
      --config examples/builtin-only.json \
      --format sarif \
      --output ${{ github.workspace }}/gate-results.sarif
  env:
    TRUSTIFY_URL: ${{ vars.TRUSTIFY_URL }}
    TRUSTIFY_TOKEN: ${{ secrets.TRUSTIFY_TOKEN }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gate-results.sarif
```

### GitLab CI

```yaml
trustify-gate:
  stage: test
  script:
    - cd tools/gate
    - uv run python gate.py check
        --sbom build/sbom.json
        --upload
        --format junit
        --output gate-results.xml
  artifacts:
    reports:
      junit: tools/gate/gate-results.xml
  variables:
    TRUSTIFY_URL: $TRUSTIFY_URL
    TRUSTIFY_TOKEN: $TRUSTIFY_TOKEN
```

### Tekton

```yaml
- name: trustify-gate
  image: python:3.13-slim
  script: |
    pip install httpx
    cd tools/gate
    python gate.py check \
      --sbom $(workspaces.source.path)/sbom.json \
      --upload \
      --config $(workspaces.source.path)/gate-config.json
  env:
    - name: TRUSTIFY_URL
      valueFrom:
        secretKeyRef:
          name: trustify
          key: url
    - name: TRUSTIFY_TOKEN
      valueFrom:
        secretKeyRef:
          name: trustify
          key: token
```

## File structure

```
tools/gate/
  gate.py               Main CLI entrypoint
  client.py             Synchronous Trustify REST API client
  config.py             Environment variable configuration
  policy.py             Data models (Violation, GateResult, config loading)
  formatters.py         Output formatters (table, JSON, SARIF, JUnit)
  checkers/
    __init__.py          Plugin protocol, registry, auto-imports
    builtin.py           Built-in threshold checker
    conforma.py          Conforma/EC OPA policy checker
  examples/
    builtin-only.json    Builtin checker only
    conforma-only.json   Conforma checker only
    full-pipeline.json   Both checkers combined
    conforma-server.json Conforma in HTTP server mode
  pyproject.toml
  Makefile
  DESIGN.md
```
