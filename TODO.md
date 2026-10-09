# TODO

- [ ] The CSAF crate expects `file_name` but the CSAF 2.0 spec uses `filename` in
  `product_identification_helper.hashes[].file_name`. The test advisory
  (`vex/vde-2025-106.json`) has been patched to use `file_name`. Once the upstream
  `csaf` crate is fixed to accept `filename`, revert this rename and use the
  original document as-is.
- [ ] Correlation, product context: SBOM-side contexts are CPE only (describing CPEs, CPEs of the
  node and its ancestors, ancestor SBOMs). Missing:
  - RPM products by PURL (`extractor/context/rpm.rs`) only map RHEL (`enterprise_linux:<major>`)
    and SLE 12/15 (`*:<major>:sp<minor>`). Missing: RHEL EUS/AUS/E4S/TUS (`rhel_eus:8.2`, …, the
    minor stream of `el8_2`), SLE 16, SUSE Linux Micro / `slfo`, and other distributions;
  - SUSE GA products are written without a service pack (`sles:15`), so they match the packages
    of every service pack of that version;
  - PURL, model number, SKU and digest contexts: advisory contexts store them, but nothing on the
    SBOM side is compared with them yet;
  - the fundamental APIs still use `product_status` and `purl_status.context_cpe_id`.
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
- [ ] Correlation options (`correlation_option`) only apply to documents extracted after a
  change. Changing an option should re-extract the advisories of its publisher.
- [ ] Assertion contexts (`assertion_context`) are only stored for advisories ingested after
  `m0002510`. Existing advisories need to be re-ingested to get the product context of their
  statements.
