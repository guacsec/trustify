# S30 — RHEL 8 curl negative and RHEL 9 fix boundaries

## Reviewed expectations

The CSAF explicitly states `known_not_affected` for versionless curl in mainline RHEL 8.
The enabled Red Hat `versionless_purl` option applies it to the installed `7.61.1-34.el8` RPM.
The RHEL 9 mainline fix is `7.76.1-14.el9_0.5`.

| Installed product/build | CVE-2022-32207 |
|---|---|
| RHEL 8 `7.61.1-34.el8`, root CPE | not_affected |
| RHEL 8 `7.61.1-34.el8`, sibling OS CPE | not_affected |
| RHEL 9 `7.76.1-10.el9_0.5` | affected |
| RHEL 9 `7.76.1-14.el9_0.5` | fixed |
| RHEL 9 `7.76.1-16.el9_0.5` | fixed |

The original RHEL 9 patched-build expectations are corrected to `fixed`.
Root versus sibling OS placement does not alter the product derived from the RPM PURL.
Both SBOM formats are covered. The advisory is unmodified.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
