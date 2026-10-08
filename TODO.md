# TODO

- [ ] The CSAF crate expects `file_name` but the CSAF 2.0 spec uses `filename` in
  `product_identification_helper.hashes[].file_name`. The test advisory
  (`vex/vde-2025-106.json`) has been patched to use `file_name`. Once the upstream
  `csaf` crate is fixed to accept `filename`, revert this rename and use the
  original document as-is.
- [ ] Correlation: product scope for assertions. Adopt the CSAF vendor → product → version
  hierarchy (and `relationships`, e.g. `default_component_of`) as the context of a vulnerability
  assertion, to filter or down-rank assertions which don't match an SBOM's context. Open points:
  the SBOM side needs a context too (e.g. the described root component), products should be
  identified by CPE/PURL rather than by free text names, non-CSAF sources (OSV, CVE) express scope
  differently, and it should probably start as a confidence modifier rather than a filter.
  Vendor specific semantics belong into correlation rules
  (`modules/correlation/src/extractor/purl/rule/`), not into ingestion. A concrete case: SUSE's
  versionless statements (`pkg:rpm/suse/openssl@`) are about a product, but `purl_suse_any_version`
  applies them to the package of any product (scenario S23, `openssl` × CVE-2025-9230).
- [ ] Fundamental: Red Hat's "fixed in X" no longer implies "affected before X" in the stored
  data (ingestion only stores what documents state). The SBOM, PURL and vulnerability APIs of the
  fundamental module therefore no longer report those inferred "affected" statuses. Migrate them
  to the correlation engine, which derives them (`purl_rh_fixed` evidence).
- [ ] CSAF ingestion still infers in `product_status` (only used by the fundamental APIs, not by
  correlation): `version_from_cpe` widens a CPE version `X` to the "stream" `[X, X+1 major)`, and
  `set_version` assumes `semver` for a PURL version. Ingestion should store what is stated, and
  leave such inferences to correlation rules.
- [ ] Correlation: vls ranges (CSAF `product_version_range` without `vers:`, stored with the
  version scheme `vls`) only match PURLs (`purl_vls_range`, scheme by PURL type). A vls range of a
  CPE (`advisory_vulnerability_cpe`) yields no evidence, as nothing hints at a version scheme.
- [ ] `VersionScheme::from(&str)` (vers schemes) maps neither `pypi` nor `cargo`, `gem`, `golang`,
  `nuget`, … (only `python`, `npm`, `maven`, `rpm`, `semver`, `git`), so those fall back to
  `generic`, which only matches exact versions.
- [ ] `vers-rs` doesn't build without its default `wasm` feature (unconditional `tsify` /
  `wasm_bindgen` attributes), so the server pulls in `wasm-bindgen` and `tsify`.
