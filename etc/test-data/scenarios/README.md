# Vulnerability Correlation Scenarios

This directory contains small, focused data sets for testing vulnerability
correlation between advisories and SBOM components.

The scenarios are deliberately separate from large production fixtures. Each
one should isolate one correlation rule, one data-quality problem, or one
regression.

## Scenario Structure

Each scenario normally contains:

```text
S<N>_<short-name>/
  README.md
  expected.json
  sbom_*.cdx.json
  sbom_*.spdx.json
  cve/                 # optional CVE records
  vex/                 # optional CSAF/VEX records
  osv/                 # optional OSV records
  control/             # optional contrast data, not normally ingested
```

Advisories may be stored as `.json.xz`. The scenario loaders try the plain
JSON file first and then the compressed form.

`expected.json` has this shape:

```json
{
  "advisories": ["vex/CVE-0000-0000.json"],
  "sboms": {
    "sbom_example": {
      "correct": {
        "CVE-0000-0000": "affected"
      }
    }
  }
}
```

Each SBOM should normally have both CycloneDX and SPDX forms. The file name
before `.cdx.json` or `.spdx.json` is the key used in `expected.json`.

## Expected Statuses

The expected status values have different meanings:

| Status | Meaning |
|---|---|
| `affected` | An applicable advisory assertion says the component is affected. |
| `not_affected` | The result is explicitly non-affected or is resolved by a matching fixed assertion. |
| `fixed` | The matching advisory result is specifically a fixed assertion. |
| `none` | No advisory assertion applies to this component. |

Do not use `not_affected` merely because a component does not match an
advisory. Use `none` when the advisory makes no applicable assertion. This is
important for product-scoped advisories, cross-ecosystem comparisons, and
versionless PURLs.

## Primary And Degraded Data

Where possible, a scenario should have a good-data primary case and a
real-world degraded-data counterpart.

Good-data scenarios should use explicit claims that make the expected result
derivable from the advisory, such as:

- VERS or ecosystem ranges for affected versions
- explicit fixed boundaries
- product or CPE context that matches the SBOM
- versioned assertions when the component is versioned

Degraded-data scenarios preserve realistic upstream problems, such as:

- versionless PURLs used as if they were wildcards
- exact fixed products without an affected range
- product statements without a matching component assertion
- mixed product and substream statements

Degraded scenarios are useful regression fixtures, but should be clearly
labelled. Their expected result may describe intended product behavior rather
than strict conclusions supported by the advisory document.

Current primary/degraded pairs include:

| Primary | Degraded counterpart | Focus |
|---|---|---|
| `S1a_vers_crossstream_bind-libs` | `S1_crossstream_bind-libs` | RHEL stream scoping |
| `S5a_vers_affected_openssl_el8` | `S5_positive_baseline_openssl_el8` | Explicit affected ranges versus fixed-only CSAF |
| `S8a_vers_epoch_openjdk` | `S8_epoch_mismatch_openjdk` | RPM epochs and fixed-only CSAF |
| `S12a_vers_affected_thunderbird` | `S12_notaffected_ignored_thunderbird` | Version ranges versus versionless negative assertions |

## Scenario Inventory

| Scenario | Focus | Current role |
|---|---|---|
| `S1_crossstream_bind-libs` | Real CSAF cross-stream behavior | Degraded, ignored |
| `S1a_vers_crossstream_bind-libs` | Explicit VERS stream boundaries | Primary, active in the standalone engine |
| `S2_wrongscheme_golang_oci` | Product-scoped bare component and scheme separation | Degraded, ignored |
| `S3_wrongproduct_hummingbird_curl` | RHEL versus Hummingbird product scope | Degraded, ignored |
| `S4_wrongproduct_satellite_chardet` | Product absence and Satellite scope | Degraded, ignored |
| `S5_positive_baseline_openssl_el8` | Fixed-only OpenSSL advisory data | Degraded, ignored |
| `S5a_vers_affected_openssl_el8` | Explicit OpenSSL VERS range | Primary, active in the standalone engine |
| `S6_positive_baseline_osv_urllib3` | OSV, PyPI, aliases, and ecosystem ranges | Primary, active in both suites |
| `S7_cpeonly_node_hummingbird` | CPE-only product correlation | Primary, active in both suites |
| `S8_epoch_mismatch_openjdk` | Real CSAF RPM epoch behavior | Degraded; active only in the fundamental suite |
| `S8a_vers_epoch_openjdk` | Explicit VERS range with RPM epoch | Primary, active in the standalone engine |
| `S9_substream_openssl_el8` | RHEL 8 substream selection | Degraded, ignored |
| `S10_combined_describing_cpe` | Combined RPM, OSV, and CPE correlation | Mixed/degraded, ignored |
| `S11_bareaffected_substream_firefox` | Bare affected GA product versus EUS fix | Degraded, ignored |
| `S12_notaffected_ignored_thunderbird` | Versionless product-level negative assertion | Degraded, ignored |
| `S12a_vers_affected_thunderbird` | Explicit Thunderbird affected range | Primary, active in the standalone engine |
| `S13_aliasless_osv_drop` | Aliasless native OSV identity | Primary, active in the standalone engine |
| `S14_productstatus_versionfilter_netty` | Bare component under matching product CPE | Good-data, currently ignored |
| `S16_crossscheme_purlquery_golang` | Cross-scheme and cross-product isolation | Synthetic, currently ignored |
| `S17_crossproduct_ocp_kernel_go` | OCP kernel versus RHEL kernel context | Real/degraded, currently ignored |

There is currently no `S15` directory.

## Running Tests

Run the active standalone correlation tests with:

```sh
cargo test -p trustify-module-correlation
```

Run the active database/API correlation scenarios with:

```sh
cargo test -p trustify-module-fundamental correlation
```

Run an ignored scenario explicitly while investigating it:

```sh
cargo test -p trustify-module-correlation scenario_s1_crossstream_bind_libs -- --ignored --nocapture
cargo test -p trustify-module-fundamental correlation::test::s1_crossstream_bind_libs -- --ignored --nocapture
```

The standalone suite currently has 123 passing tests and 15 ignored tests.
The fundamental/API correlation suite currently has 6 passing scenario cases
and 26 ignored format-specific cases.

## Adding A Scenario

1. Give the scenario a stable `S<N>_` name.
2. Keep the advisory claims and SBOM identity minimal.
3. Add a README explaining the correlation rule and every expected result.
4. Add `expected.json` and both CycloneDX and SPDX SBOMs where applicable.
5. Use `none` for an unasserted non-match and `not_affected` only for a supported negative result.
6. Add the scenario to the relevant standalone and/or fundamental test suite.
7. Mark upstream-data cases as degraded and include the issue reference when the behavior is intentionally ignored.

## Current Coverage Notes

The active suites cover RPM, PyPI, Cargo, Maven, and OCI PURLs; CycloneDX
and SPDX; OSV and CSAF/VEX; RPM epochs; VERS ranges; product CPE context;
CPE-only nodes; aliasless advisories; and root versus child CPE placement.

Most ignored cases exercise known gaps in product-status CPE filtering,
cross-scheme matching, substream selection, versionless PURL semantics,
fixed-only advisory inference, and `known_not_affected` precedence. They are
valuable regression fixtures, but should not be counted as passing coverage
until their advisory data and expected status semantics are made explicit.
