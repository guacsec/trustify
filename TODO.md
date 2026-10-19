# TODO

- [ ] Correlation, product context: SBOM-side contexts are CPEs (describing CPEs, CPEs of the node
  and its ancestors, ancestor SBOMs) and exact product identifiers (SKUs, model and serial numbers,
  digests of the node and its ancestors). Missing:
  - PURL contexts: advisory contexts store them, but nothing on the SBOM side is compared with
    them yet;
  - RPM products by PURL (`extractor/context/rpm.rs`) only map RHEL (`enterprise_linux:<major>`)
    and SLE 12/15 (`*:<major>:sp<minor>`). Missing: RHEL EUS/AUS/E4S/TUS (`rhel_eus:8.2`, …, the
    minor stream of `el8_2`), SLE 16, SUSE Linux Micro / `slfo`, and other distributions;
  - SUSE GA products are written without a service pack (`sles:15`), so they match the packages
    of every service pack of that version;
  - identifier queries (`query_with_context`) only accept CPEs and PURLs as product context;
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
- [ ] CSAF `first_fixed`, `first_affected` and `last_affected` are only stored for PURLs
  (`purl_status`, `product_status`). CPE, hash and product identifier assertions
  (`assertion_status`) have no such values, so those statements are dropped for them, and the
  CPE extractor has no rules deriving their ranges.
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
  version scheme `vls`) only match PURLs (`purl_vls_range`, scheme by PURL type). `version_matches()`
  doesn't know `vls`, so a vls range of a CPE (`advisory_vulnerability_cpe`) or of a product
  identifier (`advisory_vulnerability_product_identifier`, e.g. a firmware's model number) yields
  no evidence, as nothing hints at a version scheme.
- [ ] No versioning scheme for Debian (`deb`), Alpine (`apk`) and other distributions: their vers
  ranges and OSV `ECOSYSTEM` ranges are stored as `generic`, which only matches exact versions.
- [ ] PURL matching ignores the `arch` qualifier: an `amd64` package also matches a statement about
  the `arm64` one (scenario S18).
- [ ] A version range given as a `vers` PURL qualifier (e.g. Beckhoff's
  `pkg:deb/…@14.4.267?arch=amd64&vers=%3C14.4.267`, scenario S18) isn't a registered qualifier. It
  is kept as stated, but neither read nor flagged; the range used is the one of the CSAF branch.
- [ ] Correlation: identifier queries carry no confidence factors, so their explanation only shows
  the match confidence.
- [ ] Changing correlation options should trigger re-extraction of affected advisories and
  re-evaluation of correlation results. Expose whether results are stale and whether processing
  is pending or running.
- [ ] OSV `upstream`: the upstream IDs of a record are stored and shown on its verdicts, the
  record's statements stay under its own IDs (as OSV.dev does). Not done: grouping a CVE record's
  verdict with the downstream record covering the same component, as osv-scanner does.
- [ ] OSV distro ecosystems: the release suffix of the ecosystem (`Debian:12`, `Alpine:v3.18`,
  `Ubuntu:22.04:LTS`, `Red Hat:…`, `SUSE:…`) is dropped. It should become the assertion context, so
  that a statement only applies to the package of that release (cf. the `distro=` qualifier). Their
  `ECOSYSTEM` ranges fall back to the listed `versions` (generic, exact) instead of the rpm or deb
  version schemes.
- [ ] CVE `cpeApplicability`: the `operator` of configurations and nodes isn't read, so the
  vulnerable CPEs of an `AND` configuration ("X running on platform Y") are read as vulnerable on
  every platform; the non-vulnerable CPEs (the platform) should become the product context of the
  vulnerable ones. Negated configurations are ignored with a warning. No official CVE record with
  an `AND` platform has been found to test it with. The `cve` crate doesn't model
  `cpeApplicability`, the loader reads it from the raw record (`cve/record.rs`); add it upstream.
- [ ] CVE `cpes` and `packageURL` are synonyms of the affected software (CVE schema RFD 0002), so a
  publisher using a product CPE together with a package name (e.g. Red Hat: `enterprise_linux:8`
  and the RPM `gnutls`) states the RPM's versions as versions of the product. They are read as
  stated; a publisher-specific reading would be a correlation option.
- [ ] CVE package identity: only `packageURL`, and `collectionURL`s of Maven and Go are translated
  to PURLs. Other collections (e.g. PyPI, npm, crates.io by URL) are not, nor are container
  packages, whose versions are tags rather than the PURL version.
- [ ] CVE `repo` / `git` version ranges (commit hashes), `platforms`, `modules`, `programFiles`,
  `programRoutines`: informational, not used for matching.

## Correlation scenarios needing work

- [ ] **S7 — Deferred:** Resolve Red Hat's package-name/product-CPE interpretation and verify
  package mappings before migrating the scenario. Preserve CNA/ADP provenance; do not assume
  every package-browser entry identifies an RPM. See the
  [S7 review](etc/test-data/scenarios/S7_cpeonly_node_hummingbird/README.md).
- [ ] **S8 — Follow-up; existing cases pass:** Define missing-epoch behavior and add at/above-fix
  and conflicting-epoch controls; the current below-fix samples do not establish general epoch
  invariance. See the [S8 review](etc/test-data/scenarios/S8_epoch_mismatch_openjdk/README.md).
- [ ] **S19:** no published advisory with wildcard SKUs or model numbers has been found;
  `hbsa-2025-0004.json` is synthetic.
- [ ] **S20:** the WAGO devices are identified by wildcard model numbers (`750-821?-????-????`),
  which the synthetic SBOMs don't state, so the product is never confirmed.
