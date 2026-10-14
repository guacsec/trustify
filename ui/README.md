# Trustify correlation UI

A web UI for the correlation engine and the advisories behind it, written in Rust with
[Yew](https://yew.rs) and [PatternFly](https://www.patternfly.org) (via
[patternfly-yew](https://github.com/patternfly-yew/patternfly-yew)), built to WebAssembly with
[Trunk](https://trunkrs.dev).

## Prerequisites

* The `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
* [Trunk](https://trunkrs.dev): `cargo install trunk`
* Node.js, for the PatternFly and Font Awesome assets: `npm ci`

## Running

Start the Trustify server on port 8080, e.g. from the repository root:

```sh
cargo run -p trustify-trustd -- api --devmode --embedded-oidc
```

Then, in this directory:

```sh
npm ci
trunk serve --port 8081
```

and open <http://localhost:8081>. Trunk proxies `/api/` and `/.well-known/` to the server on
port 8080 and `/realms/` to an OIDC server on port 8090 (see `Trunk.toml`). The UI reads the OIDC
configuration from `/.well-known/trustify`, and works without authentication if the server has
none.

Trunk rebuilds on changes to `src`, `index.html`, `assets`, `Cargo.toml` and the workspace
`Cargo.lock`.

## Building

```sh
trunk build --release
```

The result is in `dist/`.

## Layout

* `src/main.rs`: application, routes, and navigation
* `src/api.rs`, `src/model.rs`: client side of the REST API
* `src/sbom_list.rs`, `src/correlation.rs`: SBOMs and their correlation
* `src/advisory_list.rs`, `src/advisory/`: the advisory explorer, format specific parts in
  sub-modules (`csaf/`, `cve/`, `osv/`)
* `assets/`: styles, and the [Monaco](https://microsoft.github.io/monaco-editor/) workers used by
  the source view (see `assets/monaco/README.md`)
