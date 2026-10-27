# Trustify Console

A web UI for the correlation engine and the advisories behind it, written in Rust with
[Yew](https://yew.rs) and [PatternFly](https://www.patternfly.org) (via
[patternfly-yew](https://github.com/patternfly-yew/patternfly-yew)), built to WebAssembly with
[Trunk](https://trunkrs.dev).

## Prerequisites

* The `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
* [Trunk](https://github.com/trunk-rs/trunk), version 0.22.1: `cargo install trunk --version 0.22.1 --locked`
* Node.js 22 and npm, for the PatternFly and Font Awesome assets

Trunk's pre-build hook runs `npm ci` automatically on the first build and whenever
`package.json` or `package-lock.json` changes. It reuses the installation for other
rebuilds. Removing `node_modules` forces a fresh install.

## Running

Start the Trustify server on port 8080, e.g. from the repository root:

```sh
cargo run -p trustify-trustd -- api --devmode --embedded-oidc
```

Then, in this directory:

```sh
trunk serve --port 8081
```

and open <http://localhost:8081>. Trunk proxies `/api/` and `/.well-known/` to the server on
port 8080 and `/realms/` to an OIDC server on port 8090 (see `Trunk.toml`). The UI reads the OIDC
configuration and capabilities from `/.well-known/trustify`, and works without authentication
if the server has none.

Correlation is enabled by default on the backend. With `--disable-correlation` or
`TRUSTD_DISABLE_CORRELATION=true`, the UI hides correlation queries, administration,
SBOM verdict/remediation columns and links, and advisory statement sections. Direct
correlation links show a disabled message without sending correlation requests.
SBOM/advisory browsing and ingestion remain available. A missing `correlation`
capability (including responses from older servers) is treated as unavailable.
Restart the backend after changing the setting, then reload the UI to rediscover it.

Trunk rebuilds on changes to `src`, `index.html`, `assets`, `Cargo.toml` and the workspace
`Cargo.lock`.

## Building

```sh
trunk build --release
```

The result is in `dist/`.

## Embedding in the server

The server and `trustd` expose two independent Cargo features, both enabled by default:

| Features | `/` | `/console/` |
|---|---|---|
| `trustify-ui` | Existing Trustify UI | — |
| `ui-console` | This console | — |
| Both | Existing Trustify UI | This console |
| Neither | No embedded UI | — |

For example, from the repository root:

```sh
# Both UIs and the normal trustd defaults (including pm)
cargo build -p trustify-trustd

# Only the existing UI
cargo build -p trustify-trustd --no-default-features --features trustify-ui

# Only this console
cargo build -p trustify-trustd --no-default-features --features ui-console

# API only
cargo build -p trustify-trustd --no-default-features
```

Add `pm` explicitly to the feature list when wanted with `--no-default-features`.
The existing UI's assets are an optional dependency; supporting endpoints such as
`/api/v3/ui/extract-sbom-purls`, frontend discovery, and Swagger are independent of
both embedded UI features.

With `ui-console`, Cargo automatically invokes Trunk, including during `cargo check`.
Debug backend builds use debug frontend builds; other profiles use frontend release
builds. The generated distribution is embedded from Cargo's `OUT_DIR`, with an isolated
nested Cargo target directory. It does not require or modify the manual `dist/` directory.
Source, asset, manifest, and lockfile changes trigger a rebuild; unchanged Cargo builds
reuse the existing output. Missing tools or a failed frontend build fail the backend build.
Builds without `ui-console` do not require Node, Trunk, or the Wasm target for this console.

The console uses its mount as the HTML base for routes and assets, and as its OIDC login
and logout callback. Configure your OIDC client to allow both the origin root and
`/console/` when building different feature combinations, for example
`http://localhost:8080/` and `http://localhost:8080/console/`. The embedded development
OIDC server accepts both. API requests continue to use `/api/` and discovery uses
`/.well-known/trustify`, regardless of the UI mount.

## Browser tests

Run `npm ci`, `npx playwright install chromium`, then `npm run test:e2e` from this
directory. The runner uses your existing `podman compose` provider to start an
isolated database and builds and starts the API and UI automatically. The same
Chromium suite runs as a required CI check, including embedded-OIDC smoke coverage.

See [the browser test guide](e2e/README.md) for prerequisites, filtering, debugging,
reports, ports, and cleanup.

## Layout

* `src/main.rs`: application, routes, and navigation
* `src/api.rs`, `src/model.rs`: client side of the REST API
* `src/sbom_list.rs`, `src/correlation.rs`: SBOMs and their correlation
* `src/importer.rs`: importers, their runs and configuration
* `src/advisory_list.rs`, `src/advisory/`: the advisory explorer, format specific parts in
  sub-modules (`csaf/`, `cve/`, `osv/`)
* `assets/`: styles, and the [Monaco](https://microsoft.github.io/monaco-editor/) workers used by
  the source view (see `assets/monaco/README.md`)
