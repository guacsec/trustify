# Trustify Locust Performance Tests

Locust-based load tests for the trustify REST API, mirroring the endpoint
coverage from [trustify-scale-testing](https://github.com/guacsec/trustify-scale-testing)
(Goose/Rust).

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- A running trustify instance
- OIDC credentials (unless running with `AUTH_DISABLED=true`)

## Quickstart (Makefile)

A Makefile provides shortcuts for common test runs. All commands assume
you are in the `tools/perf/` directory.

```bash
make help                    # list all targets
make test                    # v3 tests, 10 users, 5 min
make test-readonly           # read-only v3 tests (safe for prod)
make test-sbom               # v3 SBOM endpoint only
make ui                      # launch interactive web UI
```

Reports are written to `reports/` with auto-generated filenames that
encode what was run:

```
reports/v3-readonly_u10_5m_20260729T143022.html
reports/v3-sbom_u20_10m_20260729T150000.html
reports/v3-all_u10_5m_20260729T160000.html
```

Format: `reports/<target>_u<users>_<duration>_<timestamp>.html`

### Primary targets

| Target | Description |
|--------|-------------|
| `make test` | All v3 tests (default) |
| `make test-readonly` | Read-only v3 tests (safe for prod / read replicas) |
| `make test-v2` | All v2 tests |
| `make test-all` | v2 + v3 together |

### Per-endpoint targets

| Target | Description |
|--------|-------------|
| `make test-advisory` | v3 advisory list + detail |
| `make test-vulnerability` | v3 vulnerability list + detail + analyze |
| `make test-sbom` | v3 SBOM list + detail + license |
| `make test-purl` | v3 pURL list + detail + recommend |
| `make test-product` | v3 product list + detail |
| `make test-organization` | v3 organization list + detail |
| `make test-importer` | v3 importer list + detail |
| `make test-license` | v3 license list + slow queries |
| `make test-weakness` | v3 weakness list + detail |
| `make test-group` | v3 SBOM group list + detail |
| `make test-misc` | v3 well-known + UI helpers |
| `make test-analysis-v3` | v3 analysis + graph rendering |

### Cross-cutting targets

| Target | Description |
|--------|-------------|
| `make test-readonly-v2` | Read-only v2 tests |
| `make test-readonly-all` | Read-only v2+v3 tests |
| `make test-slow-v3` | v3 slow queries only |
| `make test-labels-v3` | v3 label mutation tests |
| `make test-analysis-v2` | v2 analysis tests |
| `make test-website` | Website UI page tests |

### Override defaults

```bash
make test HOST=https://my-server:8443 USERS=20 DURATION=10m
make test-readonly SCENARIO_FILE=etc/scenarios/main/full-20260412.json5
```

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `http://localhost:8080` | Target trustify instance |
| `USERS` | `10` | Concurrent users |
| `SPAWN_RATE` | `2` | Users spawned per second |
| `DURATION` | `5m` | Test duration |
| `SCENARIO_FILE` | (unset) | Path to JSON5 scenario file |

Run `make clean` to remove all generated reports and cached files.

## Run (uv run)

For full control, invoke `uv run locust` directly. `uv run` handles
the virtual environment and dependency installation automatically.

### Web UI (interactive)

```bash
uv run locust --host http://localhost:8080
```

Open http://localhost:8089 in your browser, set user count and spawn rate,
then start the test.

### Headless

```bash
uv run locust --host http://localhost:8080 -u 10 -r 2 -t 5m --headless
```

| Flag | Description |
|------|-------------|
| `-u 10` | 10 concurrent users |
| `-r 2` | Spawn 2 users per second |
| `-t 5m` | Run for 5 minutes |
| `--headless` | No web UI |

### Wait time between requests

By default each user waits 1-3 seconds between requests. Override with
environment variables:

```bash
# Max throughput (no delay)
TOOLS_PERF_WAIT_TIME_FROM=0 TOOLS_PERF_WAIT_TIME_TO=0 uv run locust --host http://localhost:8080 -u 10 -t 1m --headless

# Simulate slower users
TOOLS_PERF_WAIT_TIME_FROM=5 TOOLS_PERF_WAIT_TIME_TO=15 uv run locust --host http://localhost:8080 -u 10
```

### Generate an HTML report

```bash
uv run locust --host http://localhost:8080 -u 10 -t 5m --headless --html=report.html
```

### Export CSV stats

```bash
uv run locust --host http://localhost:8080 -u 10 -t 5m --headless --csv=results
```

This produces `results_stats.csv`, `results_stats_history.csv`,
`results_failures.csv`, and `results_exceptions.csv`.

## Comparing runs

Every Makefile target generates both an HTML report and matching CSV files
in `reports/`. Use the `compare` targets to diff two runs:

```bash
# Aggregate summary (default: compares the two most recent runs)
make compare

# Per-endpoint breakdown
make compare-detail

# CSV output (for spreadsheets)
make compare-csv > comparison.csv

# Compare specific runs
make compare \
  A=reports/v3-readonly_u10_5m_20260729T071219_stats.csv \
  B=reports/v3-readonly_u10_5m_20260729T071311_stats.csv

# Custom regression threshold (default: 20%)
make compare THRESHOLD=10
```

When run without `A` and `B`, all compare targets auto-detect the two most
recent `_stats.csv` files in `reports/` — the second-newest as baseline,
the newest as the current run.

`make compare` shows an aggregate summary table plus the top
regressions and improvements:

```
| Metric               | Baseline | Current | Delta  |
|----------------------|----------|---------|--------|
| Total requests       | 43,849   | 31,661  | -27.8% |
| Requests/s           | 1093.0   | 1019.1  | -6.8%  |
| Avg response (ms)    | 5.6      | 6.0     | +7.7%  |
| p95 response (ms)    | 1        | 1       | 0.0%   |
| p99 response (ms)    | 2        | 2       | 0.0%   |
| Unique endpoints     | 31       | 34      | 15 new, 12 removed |

9 regressions, 3 improvements across 19 common endpoints (p95 threshold: 20%)

Top regressions (by p95 delta):
| Endpoint                                  | p95 old | p95 new | Delta   |
|-------------------------------------------|---------|---------|---------|
| GET /api/v3/group/sbom?parents=...        | 1000    | 2700    | +170.0% |
| GET /api/v3/license?total=true            | 1200    | 2000    | +66.7%  |
```

`make compare-detail` shows the full per-endpoint table with every
endpoint's old/new values and REGRESSION/IMPROVED/NEW/REMOVED flags.

The comparison script can also be invoked directly:

```bash
uv run python compare.py reports/old_stats.csv reports/new_stats.csv
uv run python compare.py reports/old_stats.csv reports/new_stats.csv --detail
uv run python compare.py reports/old_stats.csv reports/new_stats.csv --format csv
uv run python compare.py reports/old_stats.csv reports/new_stats.csv --threshold 10
```

## HTTP compression

By default, all requests send `Accept-Encoding: gzip, deflate, br` to
match real browser/client behaviour. Responses are decompressed
transparently by the HTTP client, so reported response times include
server-side compression cost and reflect realistic end-to-end latency.

To disable compression and measure raw uncompressed transfer cost:

```bash
TOOLS_PERF_NO_COMPRESSION=1 make test-readonly
```

This is useful for isolating query/serialization time from gzip overhead,
or for comparing compressed vs uncompressed response sizes.

## Tags: readonly vs mutate

Every task is tagged with either `readonly` or `mutate` to indicate
whether it modifies server state.

**Read-only tasks** (85 of 94) use only GET requests and are safe to run
against production instances or read-only database replicas.

**Mutate tasks** (9 of 94) use POST, PUT, or PATCH and modify data
(create analysis jobs, update labels, extract PURLs).

```bash
# Run only read-only tests
uv run locust --host http://localhost:8080 -u 10 --tags readonly

# Run everything except mutations
uv run locust --host http://localhost:8080 -u 10 --exclude-tags mutate

# Or use the Makefile shortcut
make test-readonly
```

## API version selection

By default, only v3 endpoints are tested. Use the `TOOLS_PERF_API_VERSION` environment
variable to switch:

```bash
# v3 only (default)
uv run locust --host http://localhost:8080 -u 10

# v2 only
TOOLS_PERF_API_VERSION=v2 uv run locust --host http://localhost:8080 -u 10

# Both v2 and v3
TOOLS_PERF_API_VERSION=all uv run locust --host http://localhost:8080 -u 10
```

When `TOOLS_PERF_API_VERSION=all`, you can also filter by version tag:

```bash
TOOLS_PERF_API_VERSION=all uv run locust --host http://localhost:8080 -u 10 --tags v3
TOOLS_PERF_API_VERSION=all uv run locust --host http://localhost:8080 -u 10 --tags v2 advisory
```

## User classes

Tests are organized into user classes with weights that control how
frequently Locust assigns simulated users to each class. v3 tests are
split one file per endpoint group:

### v3 user classes

| Class | Weight | File | Description |
|-------|--------|------|-------------|
| `AdvisoryUserV3` | 2 | `advisory.py` | Advisory list, filter, sort, detail |
| `VulnerabilityUserV3` | 2 | `vulnerability.py` | Vulnerability list, detail, analyze |
| `SBOMUserV3` | 2 | `sbom.py` | SBOM list, detail, license, slow queries |
| `PurlUserV3` | 2 | `purl.py` | pURL list, base, detail, recommend, slow |
| `ProductUserV3` | 1 | `product.py` | Product list, detail |
| `OrganizationUserV3` | 1 | `organization.py` | Organization list, detail |
| `ImporterUserV3` | 1 | `importer.py` | Importer list, detail, report |
| `LicenseUserV3` | 1 | `license.py` | License list, SPDX, slow queries |
| `WeaknessUserV3` | 1 | `weakness.py` | Weakness/CWE list, detail |
| `GroupUserV3` | 1 | `group.py` | SBOM group list, detail |
| `MiscUserV3` | 1 | `misc.py` | Well-known, UI helpers |
| `AnalysisUserV3` | 3 | `analysis.py` | Analysis status, component, graph |
| `AdvisoryLabelUserV3` | 2 | `labels.py` | Advisory label PUT/PATCH |
| `SBOMLabelUserV3` | 2 | `labels.py` | SBOM label PUT/PATCH |

### v2 user classes

| Class | Weight | Description |
|-------|--------|-------------|
| `RestAPIUserV2` | 10 | Main REST API (v2) |
| `RestAPIUserSlowV2` | 1 | License-heavy queries (v2) |
| `AnalysisUserV2` | 1 | Analysis endpoints (v2) |

### Other

| Class | Weight | Description |
|-------|--------|-------------|
| `WebsiteUser` | 1 | UI page browsing (version-agnostic) |

### Run specific user classes

Pass class names as positional arguments:

```bash
uv run locust AdvisoryUserV3 --host http://localhost:8080 -u 10
uv run locust AnalysisUserV2 --host http://localhost:8080 -u 10
uv run locust --host http://localhost:8080 -u 10 --class-picker   # choose in web UI
```

### Filter by tag

Every task is tagged with its API version (`v2` or `v3`), endpoint group
(e.g. `advisory`, `sbom`), access pattern (`list`, `detail`, `slow`),
and access type (`readonly` or `mutate`).

```bash
uv run locust --host http://localhost:8080 -u 10 --tags advisory
uv run locust --host http://localhost:8080 -u 10 --tags sbom detail
uv run locust --host http://localhost:8080 -u 10 --exclude-tags slow mutate
```

## Authentication (OIDC)

By default, the perf tool authenticates against the trustify instance using
OIDC client credentials. Set the following environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ISSUER_URL` | Yes | -- | OIDC issuer URL (e.g. `https://sso.example.com/realms/trustify`) |
| `CLIENT_ID` | Yes | -- | OAuth2 client ID |
| `CLIENT_SECRET` | Yes | -- | OAuth2 client secret |
| `OIDC_REFRESH_BEFORE` | No | `30` | Seconds before token expiry to proactively refresh |
| `AUTH_DISABLED` | No | `false` | Set to `true` to skip OIDC and run unauthenticated |

The tool performs OIDC discovery (`/.well-known/openid-configuration`),
acquires a token via the `client_credentials` grant, and injects it as
`Authorization: Bearer <token>` on every request. Tokens are cached and
refreshed automatically before expiry.

### Authenticated run

```bash
export ISSUER_URL=https://sso.example.com/realms/trustify
export CLIENT_ID=testing
export CLIENT_SECRET=s3cret
make test HOST=https://trustify.example.com
```

### Unauthenticated run (local dev)

```bash
AUTH_DISABLED=true make test
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLS_PERF_API_VERSION` | `v3` | Which API version to test: `v2`, `v3`, or `all` |
| `TOOLS_PERF_WAIT_TIME_FROM` | `1` | Min seconds between requests per user |
| `TOOLS_PERF_WAIT_TIME_TO` | `3` | Max seconds between requests per user |
| `TOOLS_PERF_SCENARIO_FILE` | (unset) | Path to a JSON5 scenario file with pre-computed IDs |
| `TOOLS_PERF_NO_COMPRESSION` | (unset) | Set to `1` to disable gzip/deflate/br on requests |
| `ISSUER_URL` | (unset) | OIDC issuer URL |
| `CLIENT_ID` | (unset) | OAuth2 client ID |
| `CLIENT_SECRET` | (unset) | OAuth2 client secret |
| `OIDC_REFRESH_BEFORE` | `30` | Seconds before token expiry to refresh |
| `AUTH_DISABLED` | `false` | Set to `true` to skip OIDC auth |

Set both wait time variables to `0` for max throughput (no delay between requests).

## Scenario files

Some tests need pre-computed IDs (specific SBOMs, advisories, PURLs, etc.)
to hit detail endpoints. These come from a JSON5 **scenario file**, set via
the `TOOLS_PERF_SCENARIO_FILE` environment variable:

```bash
TOOLS_PERF_SCENARIO_FILE=etc/scenarios/empty.json5 uv run locust --host http://localhost:8080 -u 10
```

Without a scenario file, only the list/static endpoints run. The included
`etc/scenarios/empty.json5` has all fields set to `null` (everything
disabled). To enable detail tests, copy it and fill in real IDs from your
database:

```json5
{
  "get_sbom": "sha256:abc123...",
  "get_vulnerability": "CVE-2024-1234",
  "get_advisory": "f1e5eb17-2f31-4...",
  // ... see etc/scenarios/empty.json5 for all fields
}
```

Pre-built scenario files are organized under `etc/scenarios/`:

```bash
# Main branch scenarios (for use with the DS3/DS4 datasets)
TOOLS_PERF_SCENARIO_FILE=etc/scenarios/main/full-20260412.json5 make test

# Release-specific scenarios
TOOLS_PERF_SCENARIO_FILE=etc/scenarios/releases/0.4.z/full-20260412_atlas.json5 make test-analysis-v2
```

## Writing new tests

### Adding a task to an existing user class

Open the relevant file in `users/v3/` and add a new method with the
`@task` decorator. Always include the `readonly` or `mutate` tag:

```python
# users/v3/advisory.py

@tag("v3", "advisory", "list", "readonly")
@task
def list_advisory_by_severity(self) -> None:
    self.client.get(
        "/api/v3/advisory?q=severity=critical",
        name="/api/v3/advisory?q=severity=critical",
    )
```

The `name` parameter controls how the endpoint appears in reports. Use the
raw URL for static queries, or a descriptive name with truncated IDs for
parameterized ones (e.g. `f"get_sbom[{key[:16]}...]"`).

### Adding a scenario-dependent task

If the test needs a pre-computed ID, read it from `SCENARIO` and return
early when it is `None`:

```python
from scenario import SCENARIO

@tag("v3", "sbom", "detail", "readonly")
@task
def get_sbom_something(self) -> None:
    if not SCENARIO.get_sbom:
        return
    key = SCENARIO.get_sbom
    self.client.get(
        f"/api/v3/sbom/{quote(key, safe='')}/something",
        name=f"get_sbom_something[{key[:16]}...]",
    )
```

If the test needs a new scenario field, add it to the `Scenario` dataclass
in `scenario.py`:

```python
@dataclass(frozen=True)
class Scenario:
    # ... existing fields ...
    my_new_field: str | None = None
```

Then add the field to `etc/empty.json5` (and any other scenario files).

### Adding a new user class

Create a new file in `users/v3/`:

```python
# users/v3/my_feature.py

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

class MyFeatureUserV3(AuthenticatedHttpUser):
    weight = 2
    wait_time = WAIT_TIME

    @tag("v3", "my_feature", "readonly")
    @task
    def do_something(self) -> None:
        self.client.get("/api/v3/something", name="/api/v3/something")
```

Then import it in `locustfile.py` under the appropriate `TOOLS_PERF_API_VERSION` block:

```python
if TOOLS_PERF_API_VERSION in ("v3", "all"):
    from users.v3.my_feature import MyFeatureUserV3  # noqa: F401
```

If the class has only `readonly` tasks, add it to `V3_READONLY` in the
Makefile so `make test-readonly` picks it up. If it has only `mutate`
tasks, do **not** add it (Locust errors on user classes with zero
runnable tasks after tag filtering).

### Task weights

Use `@task(N)` to make a task run N times more often than `@task` (which
defaults to 1):

```python
@task(3)   # runs 3x as often as @task(1) tasks in the same class
def hot_endpoint(self) -> None:
    self.client.get("/api/v3/sbom", name="/api/v3/sbom")
```

### POST / PUT / PATCH requests

```python
@tag("v3", "sbom", "mutate")
@task
def create_something(self) -> None:
    self.client.post(
        "/api/v3/something",
        json={"key": "value"},
        name="create_something",
    )
```

### Response validation

Use `catch_response=True` to mark requests as pass/fail based on content:

```python
@task
def validated_get(self) -> None:
    with self.client.get(
        "/api/v3/advisory",
        name="/api/v3/advisory",
        catch_response=True,
    ) as resp:
        if resp.status_code != 200:
            resp.failure(f"status {resp.status_code}")
        elif not resp.json().get("items"):
            resp.failure("empty result set")
```

## File structure

```
tools/perf/
├── Makefile             # Test targets with auto-named reports
├── pyproject.toml       # Dependencies (locust, json5)
├── locustfile.py        # Entry point -- API version dispatch
├── compare.py           # Compare two _stats.csv runs (markdown/csv)
├── auth.py              # OIDC token provider (client_credentials)
├── config.py            # Shared wait time configuration
├── scenario.py          # Scenario data loader (JSON5)
├── reports/             # Auto-generated HTML + CSV reports (gitignored)
├── etc/
│   └── scenarios/
│       ├── empty.json5                          # Empty scenario (all fields null)
│       ├── main/                                # Main-branch scenarios
│       │   ├── full-20250323.json5
│       │   ├── full-20250604.json5
│       │   ├── full-20260317T023702Z.json5
│       │   └── full-20260412.json5              # Latest full scenario
│       └── releases/
│           └── 0.4.z/
│               ├── full-20260412_atlas.json5    # Atlas analysis-only
│               └── full-20260412_qe_atlas.json5 # QE Atlas analysis-only
└── users/
    ├── __init__.py
    ├── base.py              # AuthenticatedHttpUser (OIDC + compression)
    ├── website.py           # WebsiteUser (version-agnostic)
    ├── v3/
    │   ├── __init__.py
    │   ├── advisory.py      # AdvisoryUserV3 (weight 2)
    │   ├── analysis.py      # AnalysisUserV3 (weight 3)
    │   ├── group.py         # GroupUserV3 (weight 1)
    │   ├── importer.py      # ImporterUserV3 (weight 1)
    │   ├── labels.py        # AdvisoryLabelUserV3 (2) + SBOMLabelUserV3 (2)
    │   ├── license.py       # LicenseUserV3 (weight 1, incl. slow)
    │   ├── misc.py          # MiscUserV3 (weight 1)
    │   ├── organization.py  # OrganizationUserV3 (weight 1)
    │   ├── product.py       # ProductUserV3 (weight 1)
    │   ├── purl.py          # PurlUserV3 (weight 2, incl. slow)
    │   ├── sbom.py          # SBOMUserV3 (weight 2, incl. slow)
    │   ├── vulnerability.py # VulnerabilityUserV3 (weight 2)
    │   └── weakness.py      # WeaknessUserV3 (weight 1)
    └── v2/
        ├── __init__.py
        ├── rest_api.py      # RestAPIUserV2 (weight 10)
        ├── rest_api_slow.py # RestAPIUserSlowV2 (weight 1)
        └── analysis.py      # AnalysisUserV2 (weight 1)
```
