# S12 — Explicit RHEL 8 Thunderbird `known_not_affected`

## Reviewed expectations

The original CSAF states `known_not_affected` for versionless Thunderbird in mainline
`enterprise_linux:8`. Under the enabled Red Hat `versionless_purl` option, the installed
`115.10.1-1.el8` package gets `not_affected` in both SBOM formats. The PURL's `distro=rhel-8.10`
establishes the mainline product even though the SBOM has no CPE.
The advisory's versioned fixes are in separate extended-support products.

## Blocked control

`control/CVE-2024-6602_no-notaffected.json.xz` is synthetic: it removes all
`known_not_affected` entries and otherwise retains the original document, including its tracking ID.
It must be ingested in a separate database. `expected-control.json` records the reviewed expectation:
no verdict, because neither the RHEL 6/7 affected statements nor the extended-support fixes assert
anything applicable to this mainline RHEL 8 component.

A migration trial returned `affected` in both ingestion orders. This exposes product-scoping
behavior hidden by the original negative verdict. The control is not registered in the passing
harness; its expectation is retained for the follow-up fix. Do not change it to match engine output.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
