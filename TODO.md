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
- [ ] Correlation, RHEL 10 (regression of `fd880ed8`): RHEL 10 mainline products carry the minor
  release in their CPE version (e.g. "BaseOS (v. 10)" is `cpe:/o:redhat:enterprise_linux:10.1`,
  AppStream `10.1` / `10.2`; EUS is a separate product, `enterprise_linux_eus:10.0`). A Red Hat
  RPM's context derived from its PURL (`distro=rhel-10.2` or `el10…`) is `enterprise_linux:10`,
  and `10` vs `10.1` counts as the same product in a different version, so every RHEL 10
  mainline statement is dropped. Before, those RPMs had no context and the statements were kept
  unchecked. An SBOM's own `enterprise_linux:10.2` (e.g. syft's operating-system component) would
  conflict with `10.1` statements the same way. Within one product, a different minor is the
  same product line (10.1 → 10.2), so only a different major should make it a different
  product; the RPM version comparison decides afterwards. To decide: a general CPE rule (would
  also relate e.g. `satellite:6.13` and `satellite:6.15`), or limited to the RPM-derived Red Hat
  contexts. Found with a syft SBOM of a UBI 10 image (`etc/test-data/scenarios/syft.cdx.json`,
  untracked).
- [ ] Correlation, RHEL minor streams: stream scoping relates only equal streams, or a major and a
  minor (`el10` / `el10_1`). An `el10_1` fix is dropped for an `el10_2` build, although 10.2
  succeeds 10.1 in the mainline (only EUS/AUS/E4S minors are separate streams, and those are
  separate CPE products). Affects every package rebuilt in a later minor (e.g. 21 of the 51 RPMs
  of the UBI 10 image above, among them `openssl-libs`, `glibc`, `krb5-libs`, `libxml2`).
- [ ] Correlation, Red Hat `fixed` as `first_fixed`: Red Hat states `fixed` only for the fixing
  build. `purl_rh_fixed` derives "affected before X", but nothing derives "fixed from X on", so a
  newer build of the same stream (typical for an up-to-date image) gets no verdict. CSAF
  `first_fixed` is ingested now, with generic rules (`purl_first_fixed`,
  `purl_first_fixed_before`). Missing: a correlation option (e.g. `fixed_is_first_fixed`, enabled
  for `https://www.redhat.com` by default) reading a publisher's `fixed` as `first_fixed`,
  replacing the hard-wired `purl_rh_fixed`.
- [ ] CSAF `first_fixed`, `first_affected` and `last_affected` are only stored for PURLs
  (`purl_status`, `product_status`). CPE, hash and product identifier assertions
  (`assertion_status`) have no such values, so those statements are dropped for them, and the
  CPE extractor has no rules deriving their ranges.
- [ ] CSAF `first_fixed`, `first_affected`, `last_affected` and `under_investigation` are only
  stored for advisories ingested after `m0002540`. Existing advisories need to be re-ingested.
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
