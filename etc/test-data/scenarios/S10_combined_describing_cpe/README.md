# S10 — Mixed RHEL 8 RPMs and Python packages

## Reviewed expectations

Each verdict belongs to its component, not to every package in the SBOM:

| Component | CVE | Verdict and basis |
|---|---|---|
| OpenSSL `1:1.1.1k-7.el8` | CVE-2022-4304 | affected, below mainline fix `1:1.1.1k-9.el8_7` |
| urllib3 `1.26.17` | CVE-2023-45803 | affected, within OSV interval `[0,1.26.18)` |
| bind-libs `9.11.36-16.el8_10.8` | CVE-2024-4076 | not_affected, explicit mainline RHEL 8 assertion |
| Thunderbird `115.10.1-1.el8` | CVE-2024-6602 | not_affected, explicit mainline RHEL 8 assertion |

Thunderbird is in separate SBOMs with root-CPE and sibling-OS layouts. The package's PURL
establishes its mainline product in either layout. The mixed SBOM has the product CPE on the root.
The upstream CVE records provide no usable package identifiers for these fixtures; `expected-cve.json`
checks them alone; `expected-vex.json` and `expected-osv.json` isolate CSAF and OSV.
The combined manifest retains all sources, unmodified.
Both CycloneDX and SPDX node IDs are asserted explicitly.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
