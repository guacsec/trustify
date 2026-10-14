# S5 — OpenSSL on RHEL 8: below and at the fix

## Reviewed expectations

Both CSAF documents state `fixed` for OpenSSL `1:1.1.1k-9.el8_7` in
`enterprise_linux:8::baseos`. Their `el8_6` fixes belong to RHEL 8.6 EUS.
The SBOM packages target mainline RHEL 8, with epoch 1.

| Installed build | CVE-2022-4304 | CVE-2023-0215 |
|---|---|---|
| `1:1.1.1k-7.el8` | affected | affected |
| `1:1.1.1k-9.el8_7` | fixed | fixed |

The original patched-build expectation was `not_affected`; it is corrected to `fixed`.
The upstream CVE records identify OpenSSL by vendor/product names only, with no usable PURL or
CPE for these RPMs. They contribute no matches. `expected-cve.json` tests that independently;
`expected-vex.json` tests CSAF independently, and `expected.json` combines both sources.
Advisory inputs are unmodified; compressed paths are explicit.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
