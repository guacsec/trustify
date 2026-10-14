# S7 — CVE product CPE paired with a package name: interpretation unresolved

## Review status

Not migrated to the new verdict harness. The legacy `expected.json` remains historical input,
not an accepted oracle for the new engine. Its SBOM-level `correct` maps require component-level
review before conversion. Historical legacy-API observations do not establish current behavior.

## Checked-in evidence

The CVE records include both CNA and Red Hat ADP containers. The CNA describes upstream undici,
dbus-broker, or pgproto3; the Red Hat entries associate `packageName`/`collectionURL` with
`cpe:/a:redhat:hummingbird:1`:

| CVE | Red Hat package statement under Hummingbird |
|---|---|
| CVE-2026-12151 | rust/nodejs25 default affected; nodejs26-main unaffected from `26.5.0-1.3.hum1`, default affected |
| CVE-2026-16730 | dbus-broker default affected |
| CVE-2026-33815 | caddy default unaffected; go-fdo-server default affected |

The old expectation interprets the CPE as the product context of the named package. The new CVE
loader treats usable identifiers on an affected entry as identifiers of the same software,
applying the entry's versions/default status to the CPE itself. The package collection is not
currently translated to RPM PURLs. A product version `1` cannot be compared meaningfully to an
RPM build such as `26.5.0-1.3.hum1` without a publisher-specific interpretation.

## Required decision and follow-up

Determine whether Red Hat's package-browser entries require a publisher-specific option that
reads the CPE as product context, maps `collectionURL` + `packageName` to RPM identity, and evaluates
the package's versions. Consult the [CVE schema](https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json)
and the existing CVE identifier-synonym scenario S27. A general reinterpretation would affect S27.
Do not adopt either the legacy expectations or the engine's literal CPE output without resolving
this conflict.

After defining that policy, review all fixtures: bare product CPE, rust/dbus-broker/caddy,
nodejs25, nodejs26 below/at the boundary, detached rust, and the OpenTofu image. Establish actual
CycloneDX/SPDX identifiers and relationships; an absent match must not be labeled `not_affected`.
Keep the original CVE documents unmodified and record the option used by accepted expectations.
