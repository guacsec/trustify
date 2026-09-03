# 00022. Advisory-Based Vendor Remediation Recommendations

Date: 2026-09-03

## Status

ACCEPTED

Closes open items from [ADR 00008](00008-purls-recommendation.md):

* *"Ingest remediation information from advisories and use them to provide more data to
  results of this endpoint (requires a separate ADR)"* — this is that ADR.
* *"Provide a way to return different patterns of recommended purls"* — resolved by
  making recommendation patterns configurable per importer (see Mechanism 2). The
  hardcoded `redhat-[0-9]+$` regex is replaced by operator-supplied patterns on the
  importer configuration, requiring no code changes to support new vendors or ecosystems.

## Context

### The recommendation heuristic and its limits

ADR 00008 introduced the `/purl/recommend` endpoint, which infers recommendation
relationships between upstream and vendor packages using a regex heuristic. The current
implementation matches against a hardcoded pattern (`redhat-[0-9]+$`) to identify
Red Hat productized builds.

This approach has fundamental limitations:

* **Ecosystem-specific** — the regex is tied to Red Hat's Maven versioning convention and
  cannot generalize to other ecosystems or vendors without a code change.
* **Unreliable** — the suffix pattern guesses at a relationship that the advisory issuer
  already knows authoritatively. A package version matching the regex may not actually
  remediate the upstream version.
* **Not configurable** — operators cannot adapt the pattern to their vendor's versioning
  convention without modifying and rebuilding Trustify.

### Advisory-encoded remediation data

[Lightwell](https://www.redhat.com/en/lightwell) publishes OSV advisories that explicitly
encode the remediation relationship between upstream and vendor packages. Each such advisory
contains:

* **`database_specific.backport_base_version`** — the upstream package version that was
  backported (the version being remediated).
* **`affected[].ranges[].events[].fixed`** — the vendor package version that contains the
  fix (the remediation target).

When both fields are present in an advisory from an authoritative source, the
`(upstream_version, vendor_version)` remediation pair is unambiguous. The advisory is the
authoritative source of truth; the regex is a guess.

### The trusted source problem

Not every advisory feed carries authoritative remediation data. A general-purpose OSV
advisory (e.g., from the GitHub Advisory Database or NVD) uses the same `fixed` event to
indicate "the vulnerability is fixed in version X" — not to encode a backport remediation
relationship. Treating all advisories as trusted remediation sources would produce incorrect
recommendation records.

The system must distinguish advisory feeds that carry authoritative vendor package data
from those that do not.

### Advisory format coverage

Different advisory formats encode vendor package data differently:

* **OSV with `backport_base_version`** — the upstream→vendor mapping is explicit. This is
  the richest signal available and requires no version string interpretation.
* **CSAF security advisory (RHSA)** — vendor packages appear in the product tree with
  explicit PURLs but without an equivalent of `backport_base_version`. The upstream version
  must be identified by matching vendor version strings against a known pattern.
* **CSAF VEX** — same limitation as CSAF advisory.

This ADR defines two complementary mechanisms that together cover both cases without
hardcoding any vendor-specific logic.

## Decision

### Trusted source designation via importer configuration

Introduce the following fields on the importer configuration model:

```
trusted_source: bool          (default: false)
recommendation_patterns: []string  (default: [])
```

`trusted_source` designates the feed as carrying authoritative vendor package data and
activates recommendation extraction. `recommendation_patterns` is a list of regular
expressions that identify vendor version strings for Mechanism 2 (see below). Both fields
are also exposed on the manual advisory upload endpoint (admin-gated).

Example configuration for a Red Hat CSAF/RHSA importer:

```json
{
  "source": "https://security.access.redhat.com/data/csaf/v2/advisories/",
  "trusted_source": true,
  "recommendation_patterns": [
    "^(.+)\\.redhat-[0-9]+$",
    "^(.+)\\.SP[0-9]+-redhat-[0-9]+$"
  ]
}
```

The capture group `(.+)` extracts the upstream base version from the vendor version string.
Operators supply patterns that match their vendor's versioning convention; no code change
is required to support a new vendor or ecosystem.

### Mechanism 1: Ingest-time recommendation records (OSV with `backport_base_version`)

For each OSV advisory ingested from a trusted source, the ingestor hook:

1. Checks `database_specific.backport_base_version` — if absent, skips to Mechanism 2 at
   query time.
2. Iterates over `affected[].ranges[]`. For each range that contains a `fixed` event,
   extracts one `(upstream_version, vendor_version)` pair: `backport_base_version` as the
   upstream version and the `fixed` event value as the vendor version. If a range contains
   multiple `fixed` events, each event yields a separate pair. Ranges without a `fixed`
   event are skipped.
3. Resolves each pair to `versioned_purl` records in the database. If either PURL cannot
   be resolved (not yet ingested), that pair is skipped; other pairs continue to be
   processed.
4. Creates a `recommendation` record for each resolved pair, with a foreign key to the
   advisory for provenance.

#### Recommendation entity schema

```
recommendation
├── id                        UUID, primary key
├── upstream_versioned_purl   FK → versioned_purl (the upstream package version)
├── vendor_versioned_purl     FK → versioned_purl (the vendor/backport package version)
├── advisory                  FK → advisory (provenance — which advisory established this)
└── (unique constraint on upstream_versioned_purl + vendor_versioned_purl + advisory)
```

Multiple provenance rows may exist for the same upstream/vendor pair — at most one row per
advisory. Re-ingesting an advisory upserts only its own rows. Retracting an advisory
deletes only rows linked to that advisory; the recommendation pair remains active while at
least one other provenance row exists.

Pre-computed records are served via DB JOIN with zero per-query overhead.

### Mechanism 2: Query-time configurable pattern matching (CSAF and other formats)

When a consumer requests recommendations for an upstream PURL and no Mechanism 1 record
exists, the system applies the importer's `recommendation_patterns` at query time:

1. For each trusted-source importer with at least one `recommendation_pattern`, apply
   every pattern to the `versioned_purl` records ingested from that importer.
2. For each pattern match, extract the upstream base version from the capture group.
3. Find `versioned_purl` records in the database whose PURL coordinates (`type`,
   `namespace`, `name`) match the upstream PURL and whose version equals the extracted
   base version.
4. Return the matched vendor PURLs as recommendations.

This replaces the hardcoded `redhat-[0-9]+$` check in the current endpoint with
operator-supplied patterns scoped to their trusted-source importers. The patterns express
the same versioning-convention knowledge, but as deployment configuration rather than code.

#### Scope and limitations

Mechanism 2 relies on the vendor's versioning convention being stable and expressible as a
regular expression with one capture group for the upstream base version. This holds for
Red Hat Maven packages (`4.3.4.redhat-00008` → base `4.3.4`) and similar conventions.
Operators are responsible for validating their patterns against their vendor's actual
version strings before enabling `trusted_source`.

### Relationship between the two mechanisms

| Signal | Format | Mechanism | Query overhead |
|--------|--------|-----------|---------------|
| `backport_base_version` | OSV | Ingest-time record | Zero |
| Configurable pattern on vendor version | CSAF, any format | Query-time pattern match | One bounded query |

Mechanism 1 takes priority when a pre-computed record exists. Mechanism 2 covers the
remaining cases. Lightwell OSV advisories (Java and Python) use Mechanism 1. Red Hat
CSAF/RHSA advisories (Java/Maven) use Mechanism 2 with operator-configured patterns.

### Backward compatibility

The existing `/purl/recommend` heuristic endpoint remains unchanged. Deployments without
`trusted_source` importers continue to function as before. The endpoint is a candidate for
deprecation once Mechanisms 1 and 2 provide sufficient coverage for the deployed ecosystem.

A re-index endpoint allows operators to re-process existing trusted-source advisories and
populate Mechanism 1 records without re-ingesting from the source.

## Alternatives considered

### Separate `recommendation_config` DB entity for source patterns

Introduce a new `recommendation_config` table that maps source URLs to trusted flags and
patterns, decoupled from the importer configuration.

**Why not chosen:** The importer already owns the configuration for each advisory feed
(URL, authentication, scheduling). Adding a parallel configuration entity duplicates this
ownership and creates a new surface area to keep in sync. Placing `trusted_source` and
`recommendation_patterns` on the importer model follows the DRY principle.

### Hardcoded per-ecosystem version normalization

Replace the regex with ecosystem-specific semantic version parsers (Maven versioning for
Java, PEP 440 for Python, semver for npm, etc.) to extract base versions without a
pattern.

**Why not chosen:** Each ecosystem requires its own parsing and comparison logic, including
handling of pre-release qualifiers (`.rc`, `.beta`, `-pre`) that interact differently with
vendor suffixes across ecosystems. This is significantly more implementation work than
configurable patterns and still requires updating code to support new ecosystems. The
operator-configurable regex keeps the same knowledge in configuration rather than code with
equivalent reliability for stable versioning conventions.

### Retain the hardcoded regex without `trusted_source`

Keep `redhat-[0-9]+$` as a global pattern applied to all ingested packages, without the
trusted-source scoping.

**Why not chosen:** Applying the regex globally means any package whose version happens to
match the pattern is treated as a vendor package, regardless of its actual origin. The
`trusted_source` flag ensures pattern matching is applied only to packages from importers
the operator has explicitly designated as authoritative. This prevents false positives from
coincidental version string matches.

### OSV-only (no Mechanism 2)

Rely solely on `backport_base_version` for recommendation extraction, skipping CSAF and
other formats that lack this field.

**Why not chosen:** Lightwell currently publishes OSV advisories for Java and Python
ecosystems. Red Hat CSAF/RHSA advisories cover Java packages not yet in the Lightwell OSV
feed. Dropping Mechanism 2 would leave those packages without recommendations until OSV
coverage expands. The configurable pattern approach covers CSAF at low implementation cost.

## Open items

### Digest-based recommendation (future ADR)

Neither mechanism covers packages that Red Hat ships under the **same PURL** as the
upstream package (identical coordinates and version string) but with a **different binary
digest** — rebuilt or patched without a version bump. In this case:

* Mechanism 1 cannot apply — there is no `backport_base_version`.
* Mechanism 2 cannot apply — no version string difference means no pattern can match.

Digest comparison would improve recommendations in three ways:

1. **Same-PURL/different-binary detection** — the only signal for patched-without-version-bump
   packages. A digest mismatch between a package in the user's SBOM and the same PURL from
   a trusted-source importer identifies the trusted version as a patched drop-in replacement.

2. **Mechanism 2 match validation** — after a pattern match produces a candidate
   `(upstream, vendor)` pair, comparing digests confirms the binaries are actually
   different, ruling out re-uploads of the upstream artifact to the vendor repository that
   would produce a false recommendation.

3. **Pre-release disambiguation** — when version patterns produce multiple candidate vendor
   versions (e.g., both a GA and an RC vendor build match a pattern), digest comparison
   against the upstream binary can identify the correct match.

Digest-based recommendation requires reliable digest coverage across ingested packages
(consistent algorithm, present in both SBOMs being compared) and is deferred to a future
ADR.

## Consequences

* The hardcoded `redhat-[0-9]+$` regex is replaced by operator-configurable
  `recommendation_patterns` on trusted-source importers — no code change required to
  support new vendors or ecosystems.
* Mechanism 1 (OSV) has zero per-query overhead — recommendations are pre-computed at
  ingest time with full advisory provenance.
* Mechanism 2 (configurable patterns) has bounded query-time overhead — one query
  regardless of result set size.
* Recommendation records (Mechanism 1) carry full advisory provenance, enabling audit,
  retraction, and re-computation per advisory.
* Recommendations appear only for packages covered by an ingested trusted-source advisory
  or SBOM. Deployments without trusted-source importers configured fall back to the
  existing `/purl/recommend` heuristic.
* The existing `/purl/recommend` endpoint is unchanged and is a candidate for deprecation
  in a future release.
* Packages patched without a version bump (same PURL, different binary) are not covered
  and require the digest-based approach defined in a future ADR.
