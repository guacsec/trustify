# 00022. Advisory-Based Vendor Remediation Recommendations

Date: 2026-09-03

## Status

ACCEPTED

Closes open items from [ADR 00008](00008-purls-recommendation.md):

* *"Ingest remediation information from advisories and use them to provide more data to
  results of this endpoint (requires a separate ADR)"* — this is that ADR.
* *"Provide a way to return different patterns of recommended purls"* — resolved by
  supersession: the `trusted_source` flag on importers replaces per-vendor regex patterns
  as the mechanism for identifying recommendation relationships. The existing regex
  heuristic endpoint is retained for backward compatibility and is a candidate for
  deprecation in a future release.

## Context

### The recommendation heuristic and its limits

ADR 00008 introduced the `/purl/recommend` endpoint, which infers recommendation
relationships between upstream and vendor packages using a regex heuristic. The current
implementation matches against a hardcoded pattern (`redhat-[0-9]+$`) to identify
Red Hat productized builds.

This approach has fundamental limitations:

* **Ecosystem-specific** — the regex is tied to Red Hat's Maven versioning convention and
  cannot generalize to other ecosystems or vendors without maintaining a growing list of
  per-vendor patterns.
* **Unreliable** — the suffix pattern guesses at a relationship that the advisory issuer
  already knows authoritatively. A package version matching the regex may not actually
  remediate the upstream version.
* **Maintenance burden** — each new vendor or versioning scheme requires a code change.

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

* **OSV with `backport_base_version`** — the upstream→vendor mapping is explicit. The
  `backport_base_version` field directly names the upstream version that a vendor package
  remediates. This is the richest signal available.
* **CSAF security advisory (RHSA)** — vendor packages appear in the product tree with
  explicit PURLs (including `repository_url` pointing to the Red Hat Maven repository)
  and are associated with CVEs via `vendor_fix` remediations. However, CSAF does not
  carry an equivalent of `backport_base_version` — the upstream version must be inferred
  from the vendor version string or matched by coordinates.
* **CSAF VEX** — vendor packages appear as `known_not_affected` in the product tree with
  PURLs but without explicit upstream version mapping. The same limitation as CSAF
  advisory applies.

This ADR defines two complementary recommendation mechanisms to cover both cases.

## Decision

### Trusted source designation via importer configuration

Introduce a `trusted_source: bool` field on the importer configuration model (default:
`false`). This field designates an advisory or SBOM feed as carrying authoritative vendor
package data. When `true`, the ingestor activates recommendation extraction for that feed's
content.

The flag is also exposed on the manual advisory upload endpoint (admin-gated), allowing
operators to mark individual advisory uploads as trusted sources.

The decision to designate a feed as a trusted source is a deployment-time operator
decision, not a heuristic. The flag is not inferred automatically.

### Mechanism 1: Ingest-time recommendation records (OSV)

For each OSV advisory ingested from a trusted source, the ingestor hook:

1. Checks `database_specific.backport_base_version` — if absent, skips to Mechanism 2.
2. Iterates over `affected[].ranges[]`. For each range that contains a `fixed` event,
   extracts one `(upstream_version, vendor_version)` pair: `backport_base_version` as the
   upstream version and the `fixed` event value as the vendor version. If a range contains
   multiple `fixed` events, each event yields a separate pair. Ranges without a `fixed`
   event are skipped.
3. Resolves each pair to `versioned_purl` records in the database. If either PURL cannot
   be resolved (not yet ingested), that pair is skipped; other pairs from the same advisory
   continue to be processed.
4. Creates a `recommendation` record for each resolved pair, linking the upstream versioned
   PURL to the vendor versioned PURL with a foreign key to the advisory for provenance.

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
advisory. Re-ingesting an advisory upserts only its own provenance rows. Retracting an
advisory deletes only rows linked to that advisory; the recommendation pair remains active
while at least one other advisory provenance row exists.

The advisory foreign key provides full provenance: operators can trace every recommendation
back to the advisory that established it, retract individual advisories without losing
coverage from other authoritative sources, and re-process advisories to refresh
recommendations.

#### Query integration via DB JOIN

Pre-computed recommendation records are served to consumers via database JOIN. Any query
that needs to present recommendation data (vulnerability analysis, SBOM analysis, package
detail views) joins the `recommendation` table directly:

* Zero per-row or per-page overhead — no secondary endpoint calls in response handlers.
* Consistent data — all consumers read from the same source of truth.
* No dependency on the heuristic endpoint's runtime behavior.

### Mechanism 2: Query-time trusted-source version matching (all formats)

For packages ingested from a trusted-source importer that do not carry explicit
`backport_base_version` data (CSAF advisories, trusted-source SBOMs), recommendation
relationships are resolved at query time by coordinate and version matching.

When a consumer requests recommendations for an upstream PURL:

1. Extract the `group:artifact` coordinates (or ecosystem-equivalent) from the upstream
   PURL.
2. Query for all `versioned_purl` records with the same coordinates whose version was
   ingested from a trusted-source importer.
3. Filter to records whose version string has the upstream version as a prefix (e.g.,
   upstream `4.3.4` matches vendor `4.3.4.redhat-00008`, `4.3.4.SP1-redhat-00001`).
4. Return the matched vendor PURLs as recommendations, annotated with their trusted-source
   origin.

This mechanism replaces the hardcoded regex in the current `/purl/recommend` endpoint: the
trust signal comes from the importer configuration rather than a pattern match against the
version string. The version-prefix comparison is simpler and more accurate than the regex
— it does not require knowing the vendor-specific suffix format.

Packages ingested from a trusted-source CSAF advisory (via its product tree PURLs, which
include an explicit `repository_url` qualifier pointing to the vendor repository) are
automatically eligible for this matching path.

### Relationship between the two mechanisms

The two mechanisms are complementary and serve the same recommendation surface:

| Signal | When available | Mechanism | Latency |
|--------|---------------|-----------|---------|
| `backport_base_version` in OSV advisory | Lightwell OSV feed | Ingest-time record | Zero at query time |
| Package from trusted-source importer | CSAF, SBOM, any format | Query-time version match | One JOIN at query time |

Mechanism 1 takes priority when a pre-computed record exists for a given upstream PURL.
Mechanism 2 covers the remaining cases. Together they are format-agnostic and do not
require any per-vendor regex.

### Backward compatibility

The existing `/purl/recommend` heuristic endpoint remains unchanged. Deployments that
have not ingested trusted-source advisories or SBOMs continue to function as before. The
endpoint can be deprecated in a future release once recommendation data from Mechanisms 1
and 2 covers the required package ecosystem.

A re-index endpoint is provided to allow operators to re-process existing trusted-source
advisories and populate recommendation records without re-ingesting from the source.

## Alternatives considered

### Separate `recommendation_config` DB entity for source patterns

Introduce a new `recommendation_config` table that maps source URLs or advisory feed
identifiers to a "trusted" flag, decoupled from the importer configuration.

**Why not chosen:** The importer already owns the configuration for each advisory feed
(URL, authentication, scheduling). Adding a parallel configuration entity would duplicate
this ownership and create a new surface area to keep in sync. Extending the existing
importer model with a single boolean follows the DRY principle and avoids a new
administrative concept.

### Regex-based ingest-time computation

At ingest time, apply the existing `redhat-[0-9]+$` regex (or a configurable pattern set)
to infer remediation relationships from package version strings, without requiring
advisory-encoded data.

**Why not chosen:** Regex patterns cannot reliably determine which upstream version a
vendor package remediates without advisory authority. A vendor package version matching a
pattern may not correspond to a backport of the specific upstream version in the advisory.
The pattern approach is ecosystem-specific and requires ongoing maintenance. The advisory
already encodes the answer; reading it is strictly more accurate. Mechanism 2 achieves the
same version-string comparison but scoped to packages from trusted-source importers,
removing the need for per-vendor pattern maintenance.

### Per-query heuristic evaluation (status quo)

Continue using the current `/purl/recommend` endpoint logic at query time, calling it
per-row or per-page from response handlers.

**Why not chosen:** Per-query calls add latency proportional to the result set size.
The regex is also unreliable across ecosystems. Mechanism 1 (pre-computed records) has
zero query-time overhead; Mechanism 2 (trusted-source version match) has a single
bounded JOIN regardless of result set size.

### OSV-only ingest-time records without a query-time fallback

Rely solely on `backport_base_version` for recommendation extraction, skipping CSAF and
SBOM-sourced vendor packages.

**Why not chosen:** CSAF advisories (RHSA, VEX) do not carry an equivalent of
`backport_base_version`. Their product trees contain explicit vendor PURLs with
`repository_url` qualifiers that reliably identify Red Hat vendor packages, but the
upstream version must be inferred by coordinate and version matching. Ignoring this data
would require operators to maintain a separate OSV advisory feed for all vendor packages
they want recommendations for, which is operationally burdensome.

## Open items

### Digest-based recommendation (future ADR)

A third class of vendor package is not covered by either mechanism above: packages that
Red Hat ships under the **same PURL** as the upstream package (identical `group:artifact`
and version string) but with a **different binary digest**, because the jar was rebuilt or
patched without a version bump.

In this case:
* Mechanism 1 cannot apply — there is no `backport_base_version` (the versions are
  identical).
* Mechanism 2 cannot apply — the version prefix match returns the same PURL, not a
  distinct vendor version.

Detection requires comparing the digest of the package in the user's SBOM against the
digest of the same PURL ingested from a trusted source. A mismatch signals that the
trusted-source binary is a patched drop-in replacement for the upstream binary, and the
trusted-source package should be recommended even though the version string is identical.

This requires reliable digest coverage across ingested packages (consistent algorithm,
present in both SBOMs being compared) and is deferred to a future ADR.

## Consequences

* Recommendation data is ecosystem-agnostic: any package covered by a trusted-source OSV
  advisory with `backport_base_version` (Mechanism 1) or ingested from a trusted-source
  importer with matching coordinates (Mechanism 2) is eligible.
* The hardcoded `redhat-[0-9]+$` regex is superseded: trust is encoded in importer
  configuration, not in version string patterns.
* Mechanism 1 has zero per-query overhead — recommendations are pre-computed at ingest time.
* Mechanism 2 has bounded query-time overhead — one JOIN on trusted-source versioned PURLs
  regardless of result set size.
* Recommendation records (Mechanism 1) carry full provenance via the advisory foreign key,
  enabling audit, retraction, and re-computation.
* Recommendations only appear for packages covered by a trusted-source advisory or SBOM
  that has been ingested. Deployments without trusted-source feeds configured will have no
  recommendation data from either mechanism (the existing `/purl/recommend` heuristic
  continues to serve those deployments).
* The existing `/purl/recommend` endpoint is unchanged and is a candidate for deprecation
  in a future release once Mechanisms 1 and 2 provide sufficient coverage.
* A re-index endpoint allows operators to populate Mechanism 1 recommendation records from
  already-ingested trusted-source advisories without re-fetching from the source.
* Packages patched without a version bump (same PURL, different binary) are not covered
  and require a digest-based approach defined in a future ADR.
