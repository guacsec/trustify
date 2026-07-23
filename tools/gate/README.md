# Trustify Gate

CI/CD policy gate that evaluates SBOMs against configurable security and
compliance policies using data from a running Trustify instance. Exits
non-zero when policy violations are found.

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- A running Trustify instance
- (Optional) [Conforma CLI](https://github.com/conforma/cli) for OPA/Rego policy checks

## Quickstart

```bash
cd tools/gate
uv sync
```

### Check a local SBOM (no upload)

Extracts PURLs from the SBOM locally and runs vulnerability analysis via
the Trustify API. The SBOM itself is not uploaded.

```bash
uv run python gate.py check --sbom ./build/sbom.json
```

### Upload an SBOM then check

Uploads the SBOM to Trustify first, which enables full advisory and
license analysis in addition to vulnerability checks.

```bash
uv run python gate.py check --sbom ./build/sbom.json --upload
```

### Check an SBOM already in Trustify

```bash
# By name
uv run python gate.py check --sbom-name "my-product-1.0"

# By ID
uv run python gate.py check --sbom-id "urn:uuid:abc123..."
```

### Custom gate config

```bash
uv run python gate.py check --sbom ./sbom.json --config examples/builtin-only.json
```

### Output formats

```bash
uv run python gate.py check --sbom ./sbom.json --format json
uv run python gate.py check --sbom ./sbom.json --format sarif --output results.sarif
uv run python gate.py check --sbom ./sbom.json --format junit --output results.xml
```

## Quickstart (Makefile)

The Makefile provides shortcuts. All commands assume you are in the
`tools/gate/` directory.

```bash
make check SBOM=path/to/sbom.json                   # local SBOM, no upload
make check-upload SBOM=path/to/sbom.json             # upload then check
make check-name NAME="my-product-1.0"                # by name
make check-id ID=urn:uuid:...                        # by ID
make list-checkers                                   # show available plugins
make sync                                            # install dependencies
```

Override defaults:

```bash
make check SBOM=sbom.json TRUSTIFY_URL=https://trustify.example.com
make check SBOM=sbom.json CONFIG=examples/full-pipeline.json FORMAT=json
```

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTIFY_URL` | `http://localhost:8080` | Target Trustify instance |
| `CONFIG` | (unset) | Path to gate config file |
| `FORMAT` | `table` | Output format: table, json, sarif, junit |

## How it works

```
  Local SBOM file       or     SBOM already in Trustify
       |                              |
  extract PURLs locally          GET /sbom/{id}/packages
       |                              |
       +---------- PURLs ------------+
                     |
          POST /vulnerability/analyze
          GET /sbom/{id}/advisory
          GET /sbom/{id}/all-license-ids
                     |
              +-----------+
              |  checkers  |
              +-----------+
              |           |
           builtin    conforma    ...
              |           |
              +--- violations ---+
                     |
              pass (exit 0) / fail (exit 1)
```

1. **Resolve the SBOM** -- upload a local file, look up by name/ID, or
   extract PURLs locally from CycloneDX/SPDX JSON
2. **Fetch data from Trustify** -- vulnerability analysis, advisories,
   license inventory
3. **Run checker plugins** -- each checker evaluates the data against its
   own policy configuration
4. **Aggregate and report** -- all violations are collected, formatted,
   and the process exits non-zero if any are found

## Checker plugins

Policy evaluation uses a plugin system. The gate config file specifies
which checkers to run and their individual configuration:

```json
{
  "checkers": [
    {"name": "builtin", "config": { ... }},
    {"name": "conforma", "config": { ... }}
  ]
}
```

Multiple checkers run sequentially; all violations are aggregated.

### `builtin` -- threshold-based checker

Evaluates vulnerability severity, CVSS scores, and licenses against
declarative rules. No external tools required.

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
| `deny` | Always fail on these CVE IDs |
| `ignore` | Skip these CVE IDs |
| `ignore_unfixed` | Skip vulns with status not_affected or under_investigation |
| `licenses.deny` | Glob patterns for denied licenses (e.g. `GPL-3.0*`) |
| `licenses.allow` | If set, any license NOT matching is a violation |

### `conforma` -- OPA/Rego policy checker

Validates Trustify data against [Conforma](https://conforma.dev)
(formerly Enterprise Contract) OPA/Rego policies. Requires the `ec`
CLI binary or a running Conforma HTTP server.

All Trustify data is available to Rego rules under `input.trustify`
(SBOM metadata, PURLs, vulnerabilities, advisories, licenses).

**CLI mode** (shells out to `ec validate input`):

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

**Server mode** (POSTs to a running Conforma HTTP service):

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
| `ec_binary` | Path to `ec` binary (default: `ec` on PATH) |
| `policy` | Conforma policy source (git URL, OCI ref, local path) |
| `policy_file` | Path to an EnterpriseContractPolicy YAML file |
| `server_url` | URL of a running Conforma HTTP server |
| `extra_args` | Additional CLI arguments for `ec validate input` |

### Writing a custom checker

1. Create `checkers/mychecker.py`
2. Implement a class with a `name` property and a `check(ctx, config)` method
3. Call `register_checker("mychecker", MyClass)` at module level
4. Import the module in `checkers/__init__.py`

```python
from checkers import CheckContext, register_checker
from policy import Violation

class MyChecker:
    @property
    def name(self) -> str:
        return "mychecker"

    def check(self, ctx: CheckContext, config: dict) -> list[Violation]:
        violations = []
        # ctx.purls, ctx.vuln_analysis, ctx.advisories, ctx.license_ids
        # are all available here. Evaluate against config and append
        # Violation objects for any failures.
        return violations

register_checker("mychecker", MyChecker)
```

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| `table` | `--format table` | Human-readable terminal output (default) |
| `json` | `--format json` | Machine-readable, CI artifact storage |
| `sarif` | `--format sarif` | GitHub Code Scanning, IDE integration |
| `junit` | `--format junit` | Jenkins, GitLab CI, JUnit-compatible systems |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | Policy violations found |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTIFY_URL` | `http://localhost:8080` | Trustify server URL |
| `TRUSTIFY_TOKEN` | (empty) | Bearer token for authentication |

## Local development usage

### Scenario 1: Developer checking a build locally

```bash
# Start Trustify locally (assumes it's already running on :8080)
cd tools/gate

# Check your build SBOM against default policy (fail on critical vulns)
uv run python gate.py check --sbom ../../my-project/build/sbom.cdx.json

# Use a stricter policy
uv run python gate.py check \
  --sbom ../../my-project/build/sbom.cdx.json \
  --config examples/builtin-only.json

# Upload the SBOM for full advisory + license checks
uv run python gate.py check \
  --sbom ../../my-project/build/sbom.cdx.json \
  --upload

# Get JSON output for scripting
uv run python gate.py check \
  --sbom ../../my-project/build/sbom.cdx.json \
  --format json | jq '.summary'
```

### Scenario 2: Security team auditing an existing SBOM

```bash
# Check an SBOM that was already uploaded to Trustify
uv run python gate.py check --sbom-name "rhel-9.4-container-image"

# Use both builtin and Conforma checkers
uv run python gate.py check \
  --sbom-name "rhel-9.4-container-image" \
  --config examples/full-pipeline.json
```

### Scenario 3: Using Conforma policies

```bash
# Requires the `ec` CLI: https://github.com/conforma/cli
# Install: go install github.com/conforma/cli/cmd/ec@latest

# Run with Conforma policies from a git repo
uv run python gate.py check \
  --sbom ./sbom.json \
  --config examples/conforma-only.json

# Or start a Conforma server and use HTTP mode
ec validate input --server --server-port 8090 &
uv run python gate.py check \
  --sbom ./sbom.json \
  --config examples/conforma-server.json
```

## GitHub Actions

### Basic gate check

```yaml
name: Trustify Gate

on:
  push:
    branches: [main]
  pull_request:

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6

      - name: Generate SBOM
        run: |
          # Example: generate SBOM with syft
          syft . -o cyclonedx-json=sbom.cdx.json

      - name: Run Trustify Gate
        working-directory: tools/gate
        env:
          TRUSTIFY_URL: ${{ vars.TRUSTIFY_URL }}
          TRUSTIFY_TOKEN: ${{ secrets.TRUSTIFY_TOKEN }}
        run: |
          uv sync
          uv run python gate.py check \
            --sbom ${{ github.workspace }}/sbom.cdx.json \
            --upload \
            --config examples/builtin-only.json
```

### Gate with SARIF upload to GitHub Code Scanning

```yaml
name: Trustify Gate (SARIF)

on:
  push:
    branches: [main]
  pull_request:

jobs:
  gate:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6

      - name: Generate SBOM
        run: syft . -o cyclonedx-json=sbom.cdx.json

      - name: Run Trustify Gate
        id: gate
        continue-on-error: true
        working-directory: tools/gate
        env:
          TRUSTIFY_URL: ${{ vars.TRUSTIFY_URL }}
          TRUSTIFY_TOKEN: ${{ secrets.TRUSTIFY_TOKEN }}
        run: |
          uv sync
          uv run python gate.py check \
            --sbom ${{ github.workspace }}/sbom.cdx.json \
            --upload \
            --config examples/builtin-only.json \
            --format sarif \
            --output ${{ github.workspace }}/gate-results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gate-results.sarif

      - name: Fail if gate failed
        if: steps.gate.outcome == 'failure'
        run: exit 1
```

### Gate with JUnit report and Conforma

```yaml
name: Trustify Gate (Full Pipeline)

on:
  push:
    branches: [main]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6

      - name: Install Conforma CLI
        run: |
          curl -sL https://github.com/conforma/cli/releases/latest/download/ec_linux_amd64 \
            -o /usr/local/bin/ec
          chmod +x /usr/local/bin/ec

      - name: Generate SBOM
        run: syft . -o cyclonedx-json=sbom.cdx.json

      - name: Run Trustify Gate
        working-directory: tools/gate
        env:
          TRUSTIFY_URL: ${{ vars.TRUSTIFY_URL }}
          TRUSTIFY_TOKEN: ${{ secrets.TRUSTIFY_TOKEN }}
        run: |
          uv sync
          uv run python gate.py check \
            --sbom ${{ github.workspace }}/sbom.cdx.json \
            --upload \
            --config examples/full-pipeline.json \
            --format junit \
            --output ${{ github.workspace }}/gate-results.xml

      - name: Publish JUnit report
        uses: mikepenz/action-junit-report@v5
        if: always()
        with:
          report_paths: gate-results.xml
```

### Reusable workflow

Create `.github/workflows/trustify-gate.yml` as a reusable workflow that
other repos can call:

```yaml
name: Trustify Gate (Reusable)

on:
  workflow_call:
    inputs:
      sbom-path:
        required: true
        type: string
        description: Path to the SBOM file relative to the workspace root
      config:
        required: false
        type: string
        default: examples/builtin-only.json
        description: Gate config file (relative to tools/gate/)
      format:
        required: false
        type: string
        default: table
      upload:
        required: false
        type: boolean
        default: true
    secrets:
      TRUSTIFY_URL:
        required: true
      TRUSTIFY_TOKEN:
        required: true

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v6

      - name: Run Trustify Gate
        working-directory: tools/gate
        env:
          TRUSTIFY_URL: ${{ secrets.TRUSTIFY_URL }}
          TRUSTIFY_TOKEN: ${{ secrets.TRUSTIFY_TOKEN }}
        run: |
          uv sync
          uv run python gate.py check \
            --sbom ${{ github.workspace }}/${{ inputs.sbom-path }} \
            ${{ inputs.upload && '--upload' || '' }} \
            --config ${{ inputs.config }} \
            --format ${{ inputs.format }}
```

Callers use it like this:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: syft . -o cyclonedx-json=sbom.cdx.json

  gate:
    needs: build
    uses: ./.github/workflows/trustify-gate.yml
    with:
      sbom-path: sbom.cdx.json
    secrets:
      TRUSTIFY_URL: ${{ vars.TRUSTIFY_URL }}
      TRUSTIFY_TOKEN: ${{ secrets.TRUSTIFY_TOKEN }}
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
  README.md
```
