# S11 — Base Firefox, Flatpak module, and extended-support fix

## Reviewed expectations

The CSAF states `known_affected` for base `pkg:rpm/redhat/firefox` in mainline RHEL 8.
Its `known_not_affected` entry uses `pkg:rpm/redhat/firefox?rpmmod=firefox:flatpak`, a distinct
module identity. The installed mainline fixture lacks `rpmmod` and must not inherit the Flatpak
negative. With the Red Hat versionless-PURL option, its verdict should be `affected`.

The second fixture explicitly describes RHEL 8.8 EUS and installs `128.2.0-1.el8_8`, the exact
EUS fix. Its verdict should be `fixed`, correcting the legacy `not_affected` label.
`expected-reviewed.json` records these per-component expectations for both SBOM formats.
The original `expected.json` is retained as a historical artifact; the harness uses the reviewed manifest.

## Correlation coverage

The reviewed manifest is registered in the scenario harness for both SBOM formats and both
ingestion orders. Assertions link to their original `qualified_purl`, preserving the version
and qualifiers as stated by the advisory. Correlation compares the advisory's `rpmmod` with
the installed PURL before stream fallback, default-status shadowing, and evidence grouping.
A module-specific assertion cannot match a package without that module, or a different module.
An assertion without `rpmmod` imposes no module restriction. Integration tests cover base,
matching-module, and different-module packages, plus identifier queries and both extraction
directions. Evidence retains each original qualified advisory identifier.

An RPM's `el8_8` release alone does not prove that a box is on EUS. The EUS fixture's describing
CPE is additional evidence; review mainline and EUS evidence separately so a final `fixed` verdict
cannot hide an unrelated mainline assertion.

[CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status)
distinguish fixed from known not affected. The Red Hat `fixed_is_first_fixed` and `versionless_purl`
options are publisher policies, not universal CSAF rules. The advisory document is unmodified.

## Existing data

Migration `m0002560` adds the assertion's qualified PURL reference; older rows keep a null
reference and their legacy matching behavior. It cannot reconstruct the original association
from a base PURL alone. Remove affected advisories through the existing advisory deletion path
and ingest their original documents afresh, then extract evidence again. Merely uploading an
identical document takes the duplicate-ingestion path and does not rebuild its assertions.
Previously stored evidence must also be cleared before re-extraction, since extraction inserts
and deduplicates evidence rather than replacing the previous set.
