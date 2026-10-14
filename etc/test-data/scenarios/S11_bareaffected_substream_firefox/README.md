# S11 — Base Firefox, Flatpak module, and extended-support fix

## Reviewed expectations

The CSAF states `known_affected` for base `pkg:rpm/redhat/firefox` in mainline RHEL 8.
Its `known_not_affected` entry uses `pkg:rpm/redhat/firefox?rpmmod=firefox:flatpak`, a distinct
module identity. The installed mainline fixture lacks `rpmmod` and must not inherit the Flatpak
negative. With the Red Hat versionless-PURL option, its verdict should be `affected`.

The second fixture explicitly describes RHEL 8.8 EUS and installs `128.2.0-1.el8_8`, the exact
EUS fix. Its verdict should be `fixed`, correcting the legacy `not_affected` label.
`expected-reviewed.json` records these per-component expectations for both SBOM formats.
The original `expected.json` is retained as a historical artifact until this scenario is enabled.

## Migration blocker

A migration trial returned `not_affected` for the mainline fixture in both ingestion orders,
where the reviewed expectation is `affected`. The reviewed manifest is not registered in the
passing harness; it is retained for the follow-up fix.

The PURL extractor joins statements by base identity (type/namespace/name) and version. That loses
the `rpmmod` distinction between the base RPM and Flatpak module. Before enabling this scenario,
retain and compare advisory module qualifiers against the SBOM PURL, including tests for base,
matching-module, and different-module packages. Do not change the affected expectation merely
because the merged negative currently wins the verdict.

An RPM's `el8_8` release alone does not prove that a box is on EUS. The EUS fixture's describing
CPE is additional evidence; review mainline and EUS evidence separately so a final `fixed` verdict
cannot hide an unrelated mainline assertion.

[CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status)
distinguish fixed from known not affected. The Red Hat `fixed_is_first_fixed` and `versionless_purl`
options are publisher policies, not universal CSAF rules. The advisory document is unmodified.
