# S31 — PostgreSQL correlation and remediation consistency (TC-7208)

Source: [TC-7208](https://redhat.atlassian.net/browse/TC-7208), which reports PostgreSQL
as affected by CVE-2026-103484 while recommending the already installed version as its fix.
The attachments are preserved without content changes; the two large JSON files are XZ-compressed:

- `sbom/tpa_228_sbom_spdx_jq.json.xz`: the complete RHTPA 2.2.8 candidate SPDX SBOM (1,977 packages).
- `vex/rhsa-cve-2026-103484.json.xz`: Red Hat CSAF revision 3, generated 2026-10-23.
- `cve/CVE-2026-103484.json`: the upstream CVE 5.2 record naming pgvector before 0.8.7.

## Evidence and expectations

The installed `postgresql` and `postgresql-private-libs` RPM PURLs name
`16.15-1.module+el9.8.0+24803+9dca000b`, although their SPDX `versionInfo` is just `16.15`.
The CSAF has only `fixed` assertions, including this exact RPM build for both packages in
AppStream 9.8 / PostgreSQL 16. Its vendor fix points to RHSA-2026:85791, and its workaround
discusses restricting index creation or removing the optional pgvector extension.

However, those CSAF PURLs also require `rpmmod=postgresql:16:9080020261012122334:rhel9`.
The original SBOM PURLs omit `rpmmod`. Their Hermeto annotations instead contain
`postgresql:16:9080020260903080034:rhel9`; annotations do not supply a PURL qualifier, and that
value differs from the advisory's module build context anyway. The current RPM matcher requires
the advisory's full module qualifier to equal the SBOM qualifier. Consequently, the original
SBOM is expected to produce **no verdict**, not an explicit `fixed` or `not_affected` verdict.
This preserves an applicability limitation; absence of evidence does not establish safety.

The upstream record has no PURL or CPE identifying these RPMs. Its product name `pgvector`
does not by itself produce matching identifier evidence. The CVE-only manifest therefore
expects no verdict for any of the fixtures.

## Synthetic controls

`sbom/controls.cdx.json` and `sbom/controls.spdx.json` isolate module identity and the fix
boundary. These are synthetic SBOMs, not additional release artifacts. The downloaded
advisories remain unmodified. Each control has an x86_64 RPM PURL:

| Control | Package/version | Module qualifier | Expected verdict |
|---|---|---|---|
| before-fix | postgresql `16.14-1.module+el9.8.0+24803+9dca000b` | CSAF value | affected |
| at-fix | postgresql `16.15-1.module+el9.8.0+24803+9dca000b` | CSAF value | fixed |
| after-fix | postgresql `16.16-1.module+el9.8.0+24803+9dca000b` | CSAF value | fixed |
| missing-module | postgresql, exact fix | omitted | No verdict |
| annotation-module | postgresql, exact fix | Original Hermeto annotation value | No verdict |
| private-libs-at-fix | postgresql-private-libs, exact fix | CSAF value | fixed |

The before/after-fix controls depend on the seeded Red Hat `fixed_is_first_fixed` publisher
policy, not a general interpretation of CSAF `fixed`. The before-fix result is policy-derived;
it does not establish that PostgreSQL itself contains the vulnerable optional extension.

## Validation and limits

The service harness runs combined, CSAF-only, and CVE-only manifests in both ingestion orders.
It checks the complete verdict maps and summary counts for the original SBOM and both control
formats. S31 also requires every contributing evidence row to agree with its verdict, without
a conflict, and to retain the PostgreSQL 16 vendor fix and workaround. Live identifier queries
must agree with the materialized verdicts when supplied the CSAF product context
`cpe:/a:redhat:enterprise_linux:9::appstream`; an unscoped query is not equivalent.

```sh
cargo test -p trustify-module-correlation --locked s31 -- --test-threads=2
cargo fmt --all -- --check
```

This scenario exercises the new engine. It does not execute the legacy 3.2 vulnerability and
remediation endpoints or prove the cause of their reported inconsistency. The original input's
missing module qualifier prevents it from directly testing the equal-version fixed verdict;
the explicit-module controls cover that boundary without silently rewriting the source data.
