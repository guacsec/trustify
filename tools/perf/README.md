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
make test                    # v3 tests, 10 users, 5 min, HTML report
make test-v2                 # v2 tests
make test-all                # v2 + v3 together
make test-analysis-v2        # v2 analysis tests only
make test-rest-v3            # v3 REST API tests only
make test-labels-v3          # v3 label mutation tests only
make test-website            # website UI tests only
make ui                      # launch interactive web UI
```

Override defaults on the command line:

```bash
make test-v2 SCENARIO_FILE=etc/scenarios/main/full-20260412.json5
make test HOST=https://my-server:8443 USERS=20 DURATION=10m
make test-analysis-v2 SCENARIO_FILE=etc/scenarios/releases/0.4.z/full-20260412_atlas.json5 DURATION=1m
make test REPORT=my-report.html
```

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `http://localhost:8080` | Target trustify instance |
| `USERS` | `10` | Concurrent users |
| `SPAWN_RATE` | `2` | Users spawned per second |
| `DURATION` | `5m` | Test duration |
| `REPORT` | `report.html` | HTML report output path |
| `SCENARIO_FILE` | (unset) | Path to JSON5 scenario file |

Run `make clean` to remove generated reports and cached files.

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
frequently Locust assigns simulated users to each class. Each API version
has its own set of classes:

| Class | Weight | Version | Description |
|-------|--------|---------|-------------|
| `RestAPIUserV3` | 10 | v3 | Main REST API -- list, filter, sort, detail GETs and POSTs |
| `RestAPIUserSlowV3` | 1 | v3 | License-heavy queries (slow) |
| `AnalysisUserV3` | 2 | v3 | Analysis status, component lookup, graph render |
| `AdvisoryLabelUserV3` | 2 | v3 | Random advisory discovery + PUT/PATCH labels |
| `SBOMLabelUserV3` | 2 | v3 | SBOM label PUT/PATCH |
| `RestAPIUserV2` | 10 | v2 | Main REST API (v2) |
| `RestAPIUserSlowV2` | 1 | v2 | License-heavy queries (v2) |
| `AnalysisUserV2` | 1 | v2 | Analysis endpoints (v2) |
| `WebsiteUser` | 1 | -- | UI page browsing (version-agnostic) |

### Run specific user classes

Pass class names as positional arguments:

```bash
uv run locust RestAPIUserV3 --host http://localhost:8080 -u 10
uv run locust AnalysisUserV2 --host http://localhost:8080 -u 10
uv run locust --host http://localhost:8080 -u 10 --class-picker   # choose in web UI
```

### Filter by tag

Every task is tagged with its API version (`v2` or `v3`) and category
(e.g. `advisory`, `sbom`, `list`, `detail`, `labels`, `slow`).
Run only tasks matching specific tags:

```bash
uv run locust --host http://localhost:8080 -u 10 --tags advisory
uv run locust --host http://localhost:8080 -u 10 --tags sbom detail
uv run locust --host http://localhost:8080 -u 10 --exclude-tags slow labels
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
TOOLS_PERF_SCENARIO_FILE=etc/scenarios/main/full-20260412.json5 uv run locust --host http://localhost:8080 -u 10

# Release-specific scenarios
TOOLS_PERF_SCENARIO_FILE=etc/scenarios/releases/0.4.z/full-20260412_atlas.json5 uv run locust --host http://localhost:8080 -u 10
```

## Writing new tests

### Adding a task to an existing user class

Open the relevant file in `users/v3/` (or `users/v2/`) and add a new
method with the `@task` decorator. Always include the version tag:

```python
# users/v3/rest_api.py

@tag("v3", "advisory", "list")
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

@tag("v3", "sbom", "detail")
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

Create a new file in `users/v3/` (or `users/v2/`, or `users/` if
version-agnostic):

```python
# users/v3/my_feature.py

from locust import tag, task
from config import WAIT_TIME
from users.base import AuthenticatedHttpUser

class MyFeatureUserV3(AuthenticatedHttpUser):
    weight = 2
    wait_time = WAIT_TIME

    @tag("v3", "my_feature")
    @task
    def do_something(self) -> None:
        self.client.get("/api/v3/something", name="/api/v3/something")
```

Then import it in `locustfile.py` under the appropriate `TOOLS_PERF_API_VERSION` block:

```python
if TOOLS_PERF_API_VERSION in ("v3", "all"):
    from users.v3.my_feature import MyFeatureUserV3  # noqa: F401
```

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
@task
def create_something(self) -> None:
    self.client.post(
        "/api/v3/something",
        json={"key": "value"},
        name="create_something",
    )

@task
def update_labels(self) -> None:
    self.client.put(
        "/api/v3/sbom/some-id/label",
        json={"source": "load-test"},
        name="put_labels",
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
├── pyproject.toml      # Dependencies (locust, json5)
├── locustfile.py       # Entry point -- API version dispatch
├── auth.py             # OIDC token provider (client_credentials)
├── config.py           # Shared wait time configuration
├── scenario.py         # Scenario data loader (JSON5)
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
    ├── base.py              # AuthenticatedHttpUser (OIDC base class)
    ├── website.py           # WebsiteUser (version-agnostic)
    ├── v3/
    │   ├── __init__.py
    │   ├── rest_api.py      # RestAPIUserV3 (weight 10)
    │   ├── rest_api_slow.py # RestAPIUserSlowV3 (weight 1)
    │   ├── analysis.py      # AnalysisUserV3 (weight 2)
    │   └── labels.py        # AdvisoryLabelUserV3 (2) + SBOMLabelUserV3 (2)
    └── v2/
        ├── __init__.py
        ├── rest_api.py      # RestAPIUserV2 (weight 10)
        ├── rest_api_slow.py # RestAPIUserSlowV2 (weight 1)
        └── analysis.py      # AnalysisUserV2 (weight 1)
```
