# Browser end-to-end tests

The Playwright suite runs the embedded console in Chromium against a source-built
Trustify API, an isolated PostgreSQL 17 container, and checked-in document fixtures.
The same runner is used locally and by the required `ui-e2e` CI job.

## Prerequisites

- The repository's Rust toolchain (currently 1.96.0), including
  `rustup target add wasm32-unknown-unknown`.
- Trunk 0.22.1: `cargo install trunk --version 0.22.1 --locked`.
- Node.js 24 and npm.
- Podman with a working `podman compose` command. Its configured Compose provider
  can be Docker Compose or podman-compose; the runner does not override it.
- `xz`, used to read compressed scenario fixtures.

On macOS, start your Podman machine before running tests (`podman machine start`).
No development Trustify instance or external PostgreSQL installation is needed.
The first run may download the PostgreSQL image and Rust/Trunk build tools.

From `ui`:

```sh
npm ci
npx playwright install chromium
# Linux hosts also need browser system packages:
# npx playwright install --with-deps chromium
npm run test:e2e
```

## Selecting and debugging tests

```sh
npm run test:e2e -- --suite=core
npm run test:e2e -- --suite=capabilities
npm run test:e2e -- --suite=oidc
npm run test:e2e -- --suite=core --grep="file upload"
npm run test:e2e:headed -- --suite=core
npm run test:e2e:debug -- --grep="file upload"
npm run test:e2e:list
npm run typecheck
```

The runner forwards Playwright arguments, including `--grep`, `--headed`, and
`--debug`. Project selection, the configuration, and worker count belong to the
runner. Tests run with one worker because some settings and refresh operations
affect the whole test instance. Each test receives a new browser context.

The runner builds `trustd` with `--no-default-features --features garage-door,ui-console`,
which builds and embeds the console at `/`. The browser uses the same server and
port as the API; no Trunk development server or generated proxy config is needed.
A failed console build fails the backend build before tests start.

`E2E_SKIP_BUILD=1` skips the build when debugging against a binary you have already
built with those features. It also reuses that binary's embedded console assets.
The normal command always builds from the current source.

## Isolation and lifecycle

By default, the runner uses `podman compose` with a unique project name and disposable volume.
CI supplies PostgreSQL through a GitHub Actions service instead. To use an
externally managed test server, set `E2E_EXTERNAL_DB_PORT` to its port on
`127.0.0.1`. It must accept the `postgres` user with password `trustify-e2e`
and allow database creation. This mode requires the PostgreSQL client commands
`pg_isready`, `createdb`, and `dropdb` on the host, and does not require Podman.
Each suite's database name includes the run ID; the runner drops only databases
it created when the run ends. Use a dedicated test server.

It starts three suites sequentially, each with a new database and filesystem
storage directory:

- `core`: authentication disabled, correlation enabled, importer worker running.
- `capabilities`: authentication disabled, correlation disabled.
- `oidc`: authentication required, using Trustify's embedded test issuer and its
  real authorization-code redirect flow. The embedded issuer supplies a demo
  identity; this does not test a production provider's login form.

Database migrations run explicitly. The API runs without devmode or sample data,
and importers fetch only from a local HTTP fixture server. Scenario fixtures are
seeded through the real API. Baseline documents are shared read-only; mutating
tests use unique resources and clean them up through the API, even after failures.

Service ports are allocated dynamically by the OS and reserved until each service
starts, except for an externally supplied database port. The runner passes
the selected URLs to Playwright and the backend. The embedded issuer honors
`TRUSTD_ISSUER_URL`, so its port is dynamic too. API and issuer URLs explicitly use
`127.0.0.1`; the browser UI uses `localhost`, as required by the embedded issuer's
redirect allowlist. The shared API/UI port is checked on both loopback address families.

Ports and the Compose project name are printed and recorded in
`e2e-results/<run-id>/logs/ports.json`. Build output uses Cargo's target directory;
Storage, databases, and reports are isolated per run, allowing concurrent invocations.
Existing services are never reused or stopped.
Developer database, authentication, and service environment settings are removed
from child environments. The runner stops its processes and removes its Compose
project and volume on completion, failure, Ctrl-C, or SIGTERM.

If the process is forcibly killed (SIGKILL) or the machine stops, automatic cleanup
cannot run. Find its project name in `e2e-results/<run-id>/logs/ports.json`, then
remove just that project:

```sh
podman compose -f e2e/compose.yaml -p <project-name> down --volumes --remove-orphans
```

## Reports and CI

```sh
npm run test:e2e:report
npm run test:e2e:report -- capabilities
npm run test:e2e:report -- oidc
npx playwright show-trace e2e-results/<run-id>/test-results/<suite>/<test>/trace.zip
```

Each run has its own `e2e-results/<run-id>` directory, containing HTML reports in
`report/<suite>`, JUnit reports in `<suite>.xml`, screenshots/traces/videos in
`test-results/<suite>`, and build/API/importer/browser/PostgreSQL logs in `logs`.
Startup failures also retain their logs. The report command selects the latest
run. All output is gitignored.

GitHub Actions provisions a PostgreSQL 17 service, installs host dependencies and Chromium, checks TypeScript, and
runs the same command on Ubuntu 24.04. The full suite participates in the existing
CI gate for PRs, pushes, and merge queues. Reports and service logs are uploaded
even when startup or tests fail, with 14-day artifact retention. CI allows one
diagnostic retry but fails tests that pass only on retry; local runs do not retry.

## Adding coverage

Put tests in the relevant suite folder and import `test` and `expect` from
`../support`. Request the `seed` fixture for baseline SBOM/advisory IDs and `owned`
for test-created resources. Register resources immediately after creation so
teardown also handles a later assertion failure. Baseline expectations come from
the reviewed OpenSSL and urllib3 scenarios under `etc/test-data/scenarios`.

Prefer roles, labels, and placeholders; scope controls to their row or dialog.
Use browser interactions for the behavior under test and API calls for setup and
cleanup. Wait for assertions, requests, or bounded state polling rather than
fixed sleeps. Expected failure injection must register the affected endpoint in
the `allowedApiErrors` fixture. Unregistered API failures, page errors, and WASM
panics fail an otherwise successful test. Avoid public feeds and external services.
