# Monaco workers

The web workers of the Monaco editor used by the advisory source viewer, served as static files
and loaded only when an editor needs them.

They are copied from `js/release/` of the [`monaco`](https://crates.io/crates/monaco) crate
0.7.0, which bundles monaco-editor 0.32.1 (MIT). They must match the crate's `editor.js`: update
them whenever the `monaco` crate is updated.

Only the editor and JSON workers are included. The crate's `workers` feature, which would embed
all five workers (including the 4.8 MB TypeScript worker) into the WASM, is disabled.
