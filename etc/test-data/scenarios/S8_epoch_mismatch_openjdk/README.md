# S8 — OpenJDK below the fix, with and without the epoch qualifier

## Reviewed expectations

The three CSAF documents state the RHEL 8 AppStream fix as
`1:1.8.0.502.b07-1.1.el8`. Both installed fixtures identify the older build
`1.8.0.492.b09-1.el8`; one explicitly supplies `epoch=1`, the other omits it.
Under the configured Red Hat first-fix policy, all three CVEs are expected `affected`.
CVE-only runs require no evidence: these upstream records provide no usable identifiers for the RPM.
CSAF-only and combined runs independently check the affected results.

The original claim that epoch is irrelevant metadata and must always be borrowed from an advisory
is withdrawn. The [RPM PURL definition](https://github.com/package-url/purl-spec/blob/main/docs/types/definitions/rpm-definition.md)
makes the qualifier optional, but that does not establish a general epoch-invariant comparison rule.
These two below-fix samples alone cannot distinguish omitted-epoch comparison policies.
A general missing-epoch policy needs separate at/above-fix and conflicting-epoch controls before
it can be specified. This scenario only accepts the concrete below-fix results.
Both SBOM formats are covered; advisory inputs are unmodified.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
