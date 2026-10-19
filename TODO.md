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
  - PURL contexts: advisory contexts store them, but nothing on the SBOM side is compared with
    them yet (SKUs, model and serial numbers, and digests are, on the node and its ancestors);
  - the fundamental APIs still use `product_status` and `purl_status.context_cpe_id`.
- [ ] Correlation, RHEL minors: in the mainline, the minors are one line, so a statement of
  another minor (`el9_1` for an `el9_0` build, `el10_1` for `el10_2`) is used if the advisory
  states nothing for the build's own stream, and only within the statement's product. An RPM's
  product from its PURL is `enterprise_linux:<major>`, which matches the mainline products of
  every minor (`enterprise_linux:10.1`), but not EUS/AUS/E4S (`rhel_eus:9.0`), which are separate
  products. Open:
  - an RPM can't tell whether its box is on the mainline or on extended support of its minor: an
    EUS box's build of a minor without a statement of its own is judged by the mainline;
  - an SBOM's own minor CPE (e.g. syft's `enterprise_linux:10.2`) still differs from statements of
    another minor (`10.1`), only the RPM's product matches them. In syft's SBOMs, the
    operating-system component is no context of the RPMs, so it doesn't interfere there (scenario
    S24).
- [x] Correlation, explainable verdicts: fixed precedence compares provider relationship,
  directness, original match confidence, status, then stable evidence reference. Conflicts remain
  visible without reducing match confidence. Provider aliases, opt-in explanations, and temporary
  context previews remain; weight policies and multipliers are removed by `m0002630`.
  [S28](etc/test-data/scenarios/S28_fixed_then_regression/README.md) and
  [S29](etc/test-data/scenarios/S29_provider_weighting/README.md) cover regressions, mixed
  suppliers, CNA/ADP sources, both SBOM formats, ingestion orders, and counts. Migrations
  `m0002610`/`m0002620` retain provenance and diagnose unrecoverable provider metadata.
- [ ] CSAF `first_fixed`, `first_affected` and `last_affected` are only stored for PURLs
  (`purl_status`, `product_status`). CPE, hash and product identifier assertions
  (`assertion_status`) have no such values, so those statements are dropped for them, and the
  CPE extractor has no rules deriving their ranges.
- [ ] CSAF `first_fixed`, `first_affected`, `last_affected` and `under_investigation` are only
  stored for advisories ingested after `m0002540`. Existing advisories need to be re-ingested.
- [ ] Fundamental: Red Hat's "fixed in X" no longer implies "affected before X" in the stored
  data (ingestion only stores what documents state). As a bridge, the SBOM, PURL and
  vulnerability APIs of the fundamental module read the views `purl_status_effective` /
  `version_range_effective` (`m0002560`), which add those "affected" statuses at query time for
  publishers enabling `fixed_is_first_fixed`, without the stream scoping of the correlation
  engine. Migrate those APIs to the correlation verdicts, then drop the views.
- [ ] CSAF ingestion still infers in `product_status` (only used by the fundamental APIs, not by
  correlation): `version_from_cpe` widens a CPE version `X` to the "stream" `[X, X+1 major)`, and
  `set_version` assumes `semver` for a PURL version. Ingestion should store what is stated, and
  leave such inferences to correlation rules.
- [ ] Correlation: vls ranges (CSAF `product_version_range` without `vers:`, stored with the
  version scheme `vls`) only match PURLs (`purl_vls_range`, scheme by PURL type). A vls range of a
  CPE (`advisory_vulnerability_cpe`) yields no evidence, as nothing hints at a version scheme.
- [x] vers ranges and CSAF PURL versions take the versioning scheme of their PURL type
  (`VersionScheme::from_purl_type`), e.g. `vers:pypi/…` is compared as Python versions.
- [ ] No versioning scheme for Debian (`deb`), Alpine (`apk`) and other distributions: their vers
  ranges and OSV `ECOSYSTEM` ranges are stored as `generic`, which only matches exact versions.
- [x] `vers-rs` 0.1.3 builds with `default-features = false`, removing its `wasm-bindgen`
  and `tsify` dependencies. Updated the parser to the renamed `VersVersionRange` API.
- [ ] Changing correlation options should trigger re-extraction of affected advisories and
  re-evaluation of correlation results. Expose whether results are stale and whether processing
  is pending or running.
- [ ] Original qualified PURLs of assertions (`purl_status.qualified_purl_id`) are only linked
  for advisories ingested after `m0002600`. Existing advisories need removal and fresh ingestion
  (duplicate uploads are skipped), followed by evidence extraction. Clear previous evidence
  before re-extraction; the extractor inserts and deduplicates rather than replacing it.
- [ ] Assertion contexts (`assertion_context`) are only stored for advisories ingested after
  `m0002510`. Existing advisories need to be re-ingested to get the product context of their
  statements.
- [ ] OSV `upstream`: distro records (e.g. Ubuntu USN, Debian DSA/DLA) list their CVEs in
  `upstream`, not in `aliases`. Only `aliases` are read, so the statements of such a record are
  reported under its own ID. Decide whether a distro record's statements also count for its
  upstream CVEs (`upstream` is transitive, not symmetric).
- [ ] OSV distro ecosystems: the release suffix of the ecosystem (`Debian:12`, `Alpine:v3.18`,
  `Ubuntu:22.04:LTS`, `Red Hat:…`, `SUSE:…`) is dropped. It should become the assertion context, so
  that a statement only applies to the package of that release (cf. the `distro=` qualifier). Their
  `ECOSYSTEM` ranges fall back to the listed `versions` (generic, exact) instead of the rpm or deb
  version schemes.
- [ ] OSV remediation: the version fixing an interval (`fixed` event) is not stored, as it isn't a
  status. Offer it as a "fixed in" remediation of the `affected` evidence (as OSV.dev and
  Dependency-Track do), e.g. through `remediation_purl_status`.
- [ ] OSV advisories ingested before the OSV loader only stored the affected set still have exact
  `fixed` statuses, only the first interval of a range, and no vulnerability without a CVE alias.
  They need to be re-ingested (or a data migration).
- [ ] UI: the OSV view only parses JSON, records in YAML only have the Source tab.
- [ ] CVE `cpeApplicability`: non-vulnerable CPEs (e.g. the platform of an `AND` configuration, as
  NVD uses it) don't scope the vulnerable ones yet; only the vulnerable `cpeMatch` entries are
  stored. Negated configurations are ignored with a warning. No official CVE record with an `AND`
  platform has been found to test it with. The `cve` crate doesn't model `cpeApplicability`, the
  loader reads it from the raw record (`cve/record.rs`); add it upstream.
- [ ] CVE `cpes` and `packageURL` are synonyms of the affected software (CVE schema RFD 0002), so a
  publisher using a product CPE together with a package name (e.g. Red Hat: `enterprise_linux:8`
  and the RPM `gnutls`) states the RPM's versions as versions of the product. They are read as
  stated; a publisher-specific reading would be a correlation option.
- [ ] CVE package identity: only `packageURL`, and `collectionURL`s of Maven and Go are translated
  to PURLs. Other collections (e.g. PyPI, npm, crates.io by URL) are not, nor are container
  packages, whose versions are tags rather than the PURL version.
- [ ] CVE `repo` / `git` version ranges (commit hashes), `platforms`, `modules`, `programFiles`,
  `programRoutines`: informational, not used for matching.
- [ ] CVE records ingested before the CVE loader read `packageURL`, `changes`, `defaultStatus`,
  wildcards, and `cpeApplicability`, and wrote CPE statements to `advisory_vulnerability_cpe`, need
  to be re-ingested.

## Correlation scenarios needing work

- [ ] **S7 — Deferred:** Resolve Red Hat's package-name/product-CPE interpretation and verify
  package mappings before migrating the scenario. Preserve CNA/ADP provenance; do not assume
  every package-browser entry identifies an RPM. See the
  [S7 review](etc/test-data/scenarios/S7_cpeonly_node_hummingbird/README.md).
- [x] **S11:** Assertions reference their original qualified PURLs; correlation compares `rpmmod`
  before grouping. Base/matching/different-module controls pass, and `expected-reviewed.json`
  is enabled for both SBOM formats and ingestion orders.
  See the [S11 review](etc/test-data/scenarios/S11_bareaffected_substream_firefox/README.md).
- [x] **S12 control:** Publisher-derived affected-before-fix evidence requires product context
  or an exact RPM stream. `expected-control.json` is enabled in a separate database from the
  original advisory and produces no applicable evidence in either ingestion order. See the
  [S12 review](etc/test-data/scenarios/S12_notaffected_ignored_thunderbird/README.md).
- [ ] **S8 — Follow-up; existing cases pass:** Define missing-epoch behavior and add at/above-fix
  and conflicting-epoch controls; the current below-fix samples do not establish general epoch
  invariance. See the [S8 review](etc/test-data/scenarios/S8_epoch_mismatch_openjdk/README.md).
