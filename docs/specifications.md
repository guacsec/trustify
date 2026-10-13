# Relevant specifications and data formats

Trustify combines software bills of materials (SBOMs), vulnerability advisories,
package and product identifiers, and license information. The references below
cover specifications, formats, and conventions currently used by Trustify to
exchange and correlate that data.
They also include relevant catalogs and data services, which have their own
schemas but are not themselves formal standards.

Versioned links are reference points, not a claim that Trustify implements every
version or optional feature in a specification family. Current ingestion formats
are listed in [the format definitions](../modules/ingestor/src/service/format.rs).

## SBOMs and license information

### SPDX 2.x — Software Package Data Exchange

Links: [2.3 specification](https://spdx.github.io/spdx-spec/v2.3/), [2.3 schemas](https://github.com/spdx/spdx-spec/tree/v2.3/schemas)

An SBOM format describing packages, files, relationships, licenses, copyrights, and
external identifiers.

Trustify ingests SPDX JSON SBOMs to build its package and dependency graph and associate
components with pURLs, CPEs, and licenses.

### CycloneDX 1.x

Links: [Specification overview](https://cyclonedx.org/specification/overview/), [schemas and examples](https://github.com/CycloneDX/specification)

A bill of materials format covering components, dependencies, services, licenses, and
security information, including VEX.

Trustify ingests CycloneDX JSON SBOMs to populate its component graph. Its current
loader uses the 1.6 data model; the specification's broader capabilities do not imply
that all are ingested.

### SPDX License List and license expressions

Links: [License list](https://spdx.org/licenses/), [expression syntax](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/)

Standard license and exception identifiers, plus expressions using operators such as
`AND`, `OR`, and `WITH`. These conventions are also used outside SPDX documents.

Trustify parses and stores license information from SBOMs and package metadata.
Consistent expressions make license assertions comparable across sources.

### ClearlyDefined definitions and curations

Links: [Schemas](https://github.com/clearlydefined/service/tree/master/schemas), [curation repository](https://github.com/clearlydefined/curated-data)

Package metadata containing license and attribution information, together with community
corrections to harvested data.

Trustify has importers and loaders for definitions and curations, using them to
associate license assertions with packages.

## Vulnerability advisories and exploitability

VEX (Vulnerability Exploitability eXchange) describes whether a vulnerability
affects a particular product and may explain why it does not. It is a concept
implemented by multiple formats, including CSAF profiles and CycloneDX, rather
than one universal document schema.

### CSAF 2.0 — Common Security Advisory Framework

Links: [OASIS standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html), [JSON schema](https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json)

Structured security advisories with product trees, vulnerability status, scores, and
remediations. It also defines profiles, including VEX, and provider discovery and
distribution conventions.

Trustify imports vendor advisories and uses their product and package status information
to determine which software is affected, fixed, or known not affected. Provider metadata
supports automated advisory collection.

### OSV — Open Source Vulnerability schema

Links: [Specification](https://ossf.github.io/osv-schema/), [schema repository](https://github.com/ossf/osv-schema)

Package-oriented vulnerability records with ecosystem names, aliases, affected versions,
and ranges expressed through version or commit events.

Trustify ingests OSV advisories and correlates affected packages and version ranges with
SBOM components. Aliases connect records from different advisory sources.

### CVE Record Format 5.x (CVEProject)

Links: [Format and schemas](https://github.com/CVEProject/cve-schema), [CVE records](https://github.com/CVEProject/cvelistV5)

JSON records for CVE identifiers, with descriptions, affected products and versions,
references, weaknesses, and metrics supplied by CVE Numbering Authorities and Authorized
Data Publishers.

Trustify imports CVE records to establish vulnerability identities and their
authoritative advisory scores, then connects other advisories through shared CVE
identifiers. The record format and the published record collection are separate
resources.

### NVD — National Vulnerability Database, JSON/API 2.0

Links: [API documentation](https://nvd.nist.gov/developers/vulnerabilities), [JSON schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)

A vulnerability database and exchange schema enriching CVE records with severity
metrics, weakness mappings, and CPE applicability configurations. Its JSON format
differs from the CVE Record Format.

Trustify has a dedicated NVD importer and loader for this enrichment, including product
applicability and affected version ranges used to match SBOM components.

### GitHub Security Advisories (GHSA)

Links: [Advisory database](https://github.com/github/advisory-database)

An advisory collection identified by GHSA IDs, distributed in OSV format with ecosystem
packages, affected ranges, and aliases such as CVE IDs.

Trustify can consume these records through OSV ingestion, adding package-specific
vulnerability information and connecting GHSA and CVE identities. GHSA is a data source
and identifier convention, rather than another ingestion schema.

## Identifiers, version ranges, and weakness classification

### CPE 2.x — Common Platform Enumeration

Links: [NIST specifications, including 2.3 naming and matching](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe), [NVD CPE dictionary](https://nvd.nist.gov/products/cpe)

Structured product identifiers and rules for matching them. CPE 2.3 specifies naming,
name matching, dictionaries, and applicability language; older URI bindings also occur
in advisory data.

Trustify stores CPEs from SBOMs and advisories and uses product identity and
applicability information to correlate vulnerabilities with software.

### PURL — Package URL

Links: [Specification](https://github.com/package-url/purl-spec), [package type definitions](https://github.com/package-url/purl-spec/tree/main/types)

A `pkg:` identifier containing a package type, namespace, name, optional version,
qualifiers, and subpath, with ecosystem-specific conventions.

pURLs are central to Trustify's package identities and queries. They connect the same
package across SBOMs, advisories, and license metadata.

### VERS — Version Range Specifier

Links: [Specification](https://github.com/package-url/vers-spec)

A `vers:` representation of version constraints that names the versioning scheme,
allowing ranges to follow ecosystem-specific version ordering.

Trustify parses `vers:` ranges in CSAF product trees to represent advisory applicability
and compare it with package versions. Correct version ordering matters when determining
affected and fixed releases.

### CWE — Common Weakness Enumeration

Links: [Catalog](https://cwe.mitre.org/data/index.html), [XML downloads and schema documentation](https://cwe.mitre.org/data/downloads.html)

A taxonomy of software and hardware weakness types, such as buffer overflows and
improper input validation, with relationships between entries. A CWE identifies a
weakness category rather than an individual vulnerability.

Trustify imports the CWE XML catalog and associates vulnerability records with weakness
information, providing context beyond a CVE description or score.

## Severity and observed exploitation

### CVSS — Common Vulnerability Scoring System

Links: [2.0 specification](https://www.first.org/cvss/v2/guide), [3.0 specification](https://www.first.org/cvss/v3.0/specification-document), [3.1 specification](https://www.first.org/cvss/v3.1/specification-document), [4.0 specification](https://www.first.org/cvss/v4.0/specification-document)

Versioned metrics, vector strings, and scoring rules for vulnerability severity. CVSS
describes severity; it is not a prediction of exploitation.

Trustify parses advisory CVSS vectors, stores scores, and exposes severity information
for vulnerability assessment. Keeping the version and vector preserves the meaning of a
score.

### CISA KEV — Known Exploited Vulnerabilities catalog

Links: [Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [official JSON data and schema mirror](https://github.com/cisagov/kev-data)

A catalog of vulnerabilities known to have been exploited, with CVE identifiers,
addition dates, required actions, and remediation due dates.

Trustify imports KEV entries as exploitation evidence and exposes them alongside
vulnerabilities, helping users prioritize affected software using observed exploitation.
