# S15 — OpenSSH mainline version boundaries and CPE placement

## Reviewed expectations

The CSAF states `fixed` for OpenSSH `8.0p1-19.el8_8` in mainline RHEL 8 BaseOS/AppStream.
Its `el8_1`, `el8_2`, `el8_4`, and `el8_6` fixes are separate extended-support products.
The installed fixtures declare mainline `enterprise_linux:8` and `distro=rhel-8.8` or `rhel-8.10`.

| Fixture group | release 4 | release 19 | release 29 |
|---|---|---|---|
| Root CPE, `el8_8` | affected | fixed | fixed |
| Sibling OS CPE, `el8_8` | affected | fixed | fixed |
| Root CPE, `el8_10` | affected | fixed | fixed |

The old `el8_10` expectations treated the lack of a minor-specific statement as proof of safety.
That conflicts with the configured mainline-minor policy: absent an own-stream statement,
another mainline minor's fix can apply within the same product. The below-fix `el8_10` expectation
is therefore changed to `affected`; the at/above-fix expectations become `fixed`.
This policy does not extend to EUS/AUS/E4S/TUS products.
The child OS node is a sibling rather than an ancestor of the package. The PURL establishes the
mainline product in both formats. The advisory is unmodified.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
