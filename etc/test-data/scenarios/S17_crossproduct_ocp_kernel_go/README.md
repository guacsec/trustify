# S17 — RHEL kernel isolation from an OCP/Go advisory

## Reviewed expectations

The CSAF's kernel fix (`5.14.0-284.16.1.el9_2`) belongs to OCP 4.13 on el9.
The RHEL 8 kernel (`4.18.0-553.el8_10`) has neither that product nor that RPM stream.
Its verdict map is empty for both root-CPE and sibling-OS layouts; the original `not_affected`
expectation is removed because no applicable negative statement exists.

For `go-toolset-1.19-golang`, the document states the Devtools 2023/el7 fix
`1.19.9-1.el7_9`. The RPM's own stream is `el7_9`; the enabled publisher rule gives:

| Installed build | CVE-2023-24538 |
|---|---|
| `1.19.4-1.el7_9` | affected |
| `1.19.9-1.el7_9` | fixed |
| `1.19.11-1.el7_9` | fixed |

Patched-build expectations are corrected from `not_affected` to `fixed`.
The CycloneDX OS CPE is a sibling, not an ancestor; these package matches exercise the own-stream
policy, not a claim that the sibling establishes ancestry. Both SBOM formats are covered.
The advisory is unmodified.

## Review basis

Reviewed against the checked-in advisory documents and SBOM identifiers, rather than the legacy
API output. [CSAF product statuses](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#3239-vulnerabilities-property---product-status) distinguish `fixed` from `known_not_affected`.
The default Red Hat `fixed_is_first_fixed` option derives affected versions below the fix and
fixed versions at/after it; this is a publisher policy, not a general meaning of CSAF `fixed`.
[Red Hat scanning guidance](https://redhatproductsecurity.github.io/security-data-guidelines/scanning-vendors/) distinguishes mainline products from extended-support products.

`expected.json` uses actual filenames and component node IDs for both CycloneDX and SPDX.
Missing entries mean no applicable evidence, not an explicit `not_affected` assertion.
The scenario harness runs both ingestion orders and checks exact verdicts and summary counts.
