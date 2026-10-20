# S8 — OpenJDK below the fix, with and without the epoch qualifier

## Reviewed expectations

The three CSAF documents state the RHEL 8 AppStream fix as
`1:1.8.0.502.b07-1.1.el8`. Both installed fixtures identify the older build
`1.8.0.492.b09-1.el8`; one explicitly supplies `epoch=1`, the other omits it.
Under the configured Red Hat first-fix policy, all three CVEs are expected `affected`.
CVE-only runs require no evidence: these upstream records provide no usable identifiers for the RPM.
CSAF-only and combined runs independently check the affected results.

RPM defines an omitted epoch as zero: “Non-existent epoch is exactly equal to zero epoch in all
version comparisons.” See the [RPM spec-file documentation](https://rpm.org/docs/4.20.x/manual/spec.html#epoch).
The implementation follows this rule. Epoch is compared before version and release, and must not
be ignored or borrowed from the advisory. An SBOM that accidentally drops a nonzero epoch has
lost package information; that does not change RPM's comparison semantics.

The existing below-fix fixtures pass, but would also pass if epoch handling were broken because
their version-release is already below the fix. Additional regression controls should cover
at/above-fix version-releases with omitted, explicit zero, and nonzero epochs. Omitted epoch and
explicit zero must behave identically: both compare below this epoch-1 fix even when their
version-release is at or above its version-release. With epoch 1, the same boundary samples
should be fixed under the configured first-fix policy. A higher-epoch sample with a lower
version-release would additionally verify that epoch takes precedence.
This is a test-coverage follow-up, not an unresolved missing-epoch policy or an identified
implementation defect.
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
