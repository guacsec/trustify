# S28 — An initial fix followed by an explicit regression

All documents are synthetic. `CVE-2026-99991` is a test identifier, not a claim about a
published vulnerability. The advisory uses the Red Hat publisher namespace solely to exercise
the seeded `fixed_is_first_fixed` option.

The CSAF document states `demo-regression` fixed in `1.0-2.el9`, affected in `1.0-3.el9`, and
fixed again in `1.0-4.el9`, all in the same RHEL 9 product. The publisher policy derives fixed
evidence at and above each fix, and affected evidence below each fix. The explicit affected
assertion for the regression must override the inferred fixed evidence from the earlier fix.
Both assertions remain visible in the verdict's evidence and in live identifier queries.

| Component | RPM version | Verdict | Control |
|---|---|---|---|
| before-fix | 1.0-1.el9 | affected | Below the initial fix |
| initial-fix | 1.0-2.el9 | fixed | A directly stated fix still wins |
| regression | 1.0-3.el9 | affected | Explicit regression overrides inferred fixed |
| subsequent-fix | 1.0-4.el9 | fixed | The subsequent directly stated fix |
| inferred-fixed | 1.0-5.el9 | fixed | Policy still applies without an explicit regression |
| other-stream | 1.0-3.el8 | No evidence | RHEL 9 assertions cannot cross into RHEL 8 |

A separate RHEL 8 assertion declares `1.0-5.el8` affected. It must not override the inferred
fixed verdict for `1.0-5.el9`, despite sharing the package identity and release number.

`expected.json` covers CycloneDX and SPDX. The scenario harness checks both ingestion orders,
exact verdicts, and summary counts. A dedicated test also checks retained evidence and the live
identifier-query controls in both formats and ingestion orders.
