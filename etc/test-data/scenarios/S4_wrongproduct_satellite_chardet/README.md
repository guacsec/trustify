# S4 — Satellite chardet statements do not apply to RHEL 8

## Reviewed expectations

All three CSAF documents state `fixed` for `python3-chardet@3.0.4-10.el7ar` only in
Satellite 6.7/6.8. The installed package is `python3-chardet@3.0.4-7.el8`, mainline RHEL 8.
Neither the product nor the RPM stream matches. All component/vulnerability maps are empty.
The old `not_affected` expectations asserted a negative that the documents do not supply.

The upstream CVEs describe Puppet, MySQL Connectors, and Apache MINA without usable identifiers
for this RPM. CVE-only, CSAF-only, and combined expectations independently require no evidence.
Both root-CPE and sibling-OS layouts are tested in both SBOM formats. Advisory inputs are unmodified.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
