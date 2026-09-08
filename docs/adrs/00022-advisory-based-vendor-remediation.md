# 00022. Advisory-Based Vendor Remediation Recommendations

Date: 2026-09-03

## Status

PROPOSED

Partially closes open items from [ADR 00008](00008-purls-recommendation.md):

* *"Provide a way to return different patterns of recommended purls"* — partially resolved:
  the hardcoded `redhat-[0-9]+$` regex is replaced by operator-configurable patterns per
  importer. Full resolution requires solving the ingest-time vs query-time performance
  trade-off described in the Open Problems section below.
* *"Ingest remediation information from advisories and use them to provide more data to
  results of this endpoint (requires a separate ADR)"* — deferred. Design exploration in
  this ADR found no approach that resolves all trade-offs satisfactorily. See Open Problems.

## Context

### The recommendation heuristic and its limits

ADR 00008 introduced the `/purl/recommend` endpoint, which infers recommendation
relationships between upstream and vendor packages using a regex heuristic. The current
implementation matches against a hardcoded pattern (`redhat-[0-9]+$`) to identify
Red Hat productized builds.

This approach has two problems:

* **Not configurable** — operators cannot adapt the pattern to their vendor's versioning
  convention without modifying and rebuilding Trustify.
* **Unreliable** — a version string matching the regex may not actually remediate the
  upstream version. The advisory issuer knows this relationship authoritatively; the regex
  guesses it.

### What advisory formats actually encode

This ADR explored whether advisory or SBOM files could provide a more reliable source of
recommendation relationships, replacing or supplementing the regex.

**OSV advisories:**

* `affected[].ranges[].events[].fixed` — standard OSV field. Means "the vulnerability is
  fixed in this version." Does NOT encode a backport relationship — `fixed` on a general
  OSV advisory (GitHub Advisory Database, NVD, Go Vuln DB) simply identifies the upstream
  version where the CVE was resolved, not a vendor build.
* `database_specific.backport_base_version` — a non-standard extension specific to
  [Lightwell](https://www.redhat.com/en/lightwell)'s OSV advisory feed. Explicitly names
  the upstream version that a vendor package remediates. This IS an authoritative upstream→
  vendor mapping, but it is not part of the OSV specification and cannot be expected from
  any other OSV producer. Lightwell is a Red Hat product; its advisory feed is not
  appropriate to treat as an upstream Trustify concern.

**CSAF security advisory (RHSA):**

Vendor packages appear in the product tree with explicit PURLs (including
`repository_url` pointing to the Red Hat Maven repository). `vendor_fix` remediations
associate packages with CVEs. However, CSAF carries no equivalent of
`backport_base_version` — the upstream version must be inferred from the vendor version
string. The explicit upstream→vendor mapping is absent.

**CSAF VEX:**

Vendor packages appear as `known_not_affected` or `fixed` in the product tree with PURLs.
Both statuses are meaningful as recommendation signals (a `known_not_affected` vendor
build is safe regardless of the CVE; a `fixed` vendor build remediates it). The same
limitation applies: no explicit upstream version mapping is encoded.

**SBOM files:**

SBOMs record the composition of a software artifact — what packages it contains. They
do not encode remediation or recommendation relationships between upstream and vendor
packages. SBOM files cannot be used as a source of recommendation data.

## Decision

Replace the hardcoded `redhat-[0-9]+$` pattern in `/purl/recommend` with a configurable
list of regular expressions per importer.

### Configuration

Add `recommendation_patterns: []string` to the importer configuration model (default:
empty). Each pattern is a regular expression with exactly one capture group that extracts
the upstream base version from a vendor version string.

Example for a Red Hat CSAF importer:

```json
{
  "source": "redhat.com",
  "recommendation_patterns": [
    "^(.+)\\.redhat-[0-9]+$",
    "^(.+)\\.SP[0-9]+-redhat-[0-9]+$"
  ]
}
```

Patterns are configured by the operator (or by Red Hat in downstream deployments via
`saas.yaml` in app-interface) and require no code change to support new vendors or
versioning conventions.

### Query-time application

Patterns are applied at query time in the `/purl/recommend` endpoint. For each upstream
PURL in the request, the endpoint searches for versioned PURLs with matching
`type:namespace:name` coordinates whose version string matches any configured pattern
and whose extracted base version equals the upstream version.

Query-time application was chosen over ingest-time application to avoid the data
consistency problem described in the Open Problems section.

### Qualifier matching

When matching vendor to upstream packages by extracted base version, qualifier handling
follows these rules:

* **`type`** — must match after normalizing to the ecosystem default (e.g., Maven defaults
  to `jar`). A `type=pom` vendor package must not be recommended for a `type=jar` upstream
  consumer — they are different artifacts.
* **`repository_url`** — ignored. This qualifier identifies the source repository and is
  not part of artifact identity.
* **`classifier`** and all other qualifiers — must match. `sources`, `javadoc`, and
  `tests` classifiers identify distinct artifacts.

## Open Problems

### Ingest-time vs query-time performance trade-off

Applying patterns at query time avoids data consistency problems but does not scale to
SBOM-level queries. An SBOM with thousands of packages requires one recommendation lookup
per package — this is not viable for SBOM table views or analysis endpoints.

The performant alternative is to apply patterns at ingest time: when a new `versioned_purl`
is ingested, apply `recommendation_patterns`, extract the upstream base version, resolve
the upstream `versioned_purl`, and create a `recommendation` record in a dedicated table.
Consumers query the table via a single JOIN with zero per-package overhead.

The ingest-time approach introduces a data consistency problem: if `recommendation_patterns`
is updated (new pattern added, old pattern corrected), all existing `recommendation` records
built from the old patterns are stale. A full re-index of all `versioned_purl` records is
required to rebuild the table correctly. This re-index cost scales with the size of the
package database and makes pattern updates operationally expensive.

Neither option is satisfactory without further design work. This trade-off is the primary
blocker for a fully accepted decision.

### Lightwell `backport_base_version` and advisory-based ingest

Lightwell's `backport_base_version` OSV field provides an explicit, regex-free upstream→
vendor mapping. At ingest time, this field could populate a `recommendation` table without
any pattern matching — making the ingest-time records immune to the staleness problem
(records are tied to advisory provenance, not regex config).

However:

* `backport_base_version` is not a standard OSV field. No other OSV producer uses it.
* Lightwell is a Red Hat product. Its advisory feed is not a concern for upstream Trustify.
  A Lightwell-specific importer belongs in the RHTPA downstream deployment (app-interface),
  not in the open-source codebase.

A hybrid design — advisory-backed records from Lightwell (stable, no staleness) plus
regex-backed records for other packages (subject to staleness) — is worth exploring but
requires the Lightwell importer to exist first. Deferred until Lightwell integration is
planned.

### CSAF and SBOM coverage

CSAF advisories (RHSA and VEX) provide vendor PURLs in their product trees but carry no
explicit upstream version mapping. A regex applied to the vendor version string can infer
the upstream version, but this reduces CSAF coverage to the same regex trade-offs as the
general case above.

SBOM files carry no remediation relationship data at all and cannot contribute to the
recommendation table regardless of approach.

### Pre-release version edge cases

Regex and version-prefix matching are unreliable when vendor version strings include
pre-release qualifiers (`.rc`, `.beta`, `-pre`, etc.). The correct behavior — whether a
pre-release vendor build should recommend against a GA upstream or a pre-release upstream
— requires ecosystem-specific semantic version parsing (Maven versioning, PEP 440, semver).
This complexity is out of scope for a configurable regex approach.

Operators are responsible for validating that their `recommendation_patterns` handle
pre-release versions correctly for their vendor's conventions before enabling them.

### Digest-based recommendations

A class of vendor packages exists where the vendor ships a patched binary under the same
PURL as the upstream package (identical coordinates and version string, different binary
digest). Neither regex-based nor advisory-based approaches can detect this relationship —
the version strings are identical, so no pattern can distinguish them.

Detection requires comparing the digest of the package in the user's SBOM against the
digest of the same PURL ingested from an authoritative source. This is a distinct problem
requiring digest coverage across ingested packages and a separate design. Deferred to a
future ADR.

## Consequences

* The hardcoded `redhat-[0-9]+$` regex is replaced by operator-configurable
  `recommendation_patterns` on each importer — no code change required to support new
  vendors or versioning conventions.
* Query-time application preserves the existing endpoint semantics with no new data
  consistency concerns.
* Performance at SBOM scale remains an open problem until the ingest-time trade-off is
  resolved.
* Advisory-based ingest-time recommendations (Lightwell OSV, CSAF) are deferred until
  the staleness problem is solved or a Lightwell-specific downstream importer is available
  to provide stable advisory-backed records.
* Digest-based recommendations are deferred to a future ADR.
