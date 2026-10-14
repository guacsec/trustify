# S9 — OpenSSL: the RPM's own 8.2 build stream

## Reviewed expectations

The CSAF states `fixed` for `1:1.1.1c-21.el8_2` in RHEL 8.2 AUS/E4S/TUS and
`1:1.1.1k-9.el8_7` in mainline RHEL 8. The installed RPMs have the `el8_2` stream.
The enabled Red Hat rule uses their own stream's fix. This test exercises that policy;
the RPM's release alone does not establish which extended-support subscription is installed.
The CycloneDX OS node is a sibling of the RPM, not its ancestor; SPDX has no equivalent OS CPE.

| Installed build | CVE-2023-0286 |
|---|---|
| `1:1.1.1c-15.el8_2` | affected |
| `1:1.1.1c-21.el8_2` | fixed |

The original patched-build expectation is corrected from `not_affected` to `fixed`.
The upstream CVE names OpenSSL without a usable PURL/CPE for these RPMs and contributes no matches.
`expected-cve.json`, `expected-vex.json`, and `expected.json` test the two sources separately and
together. Existing focused extractor tests check the chosen stream and matched ranges.
Advisory inputs are unmodified.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
