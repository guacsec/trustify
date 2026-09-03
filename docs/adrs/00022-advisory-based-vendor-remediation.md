# 00022. Advisory-Based Vendor Remediation Recommendations

Date: 2026-09-03

## Status

ACCEPTED

Closes the open advisory-ingest item from [ADR 00008](00008-purls-recommendation.md):

* *"Ingest remediation information from advisories and use them to provide more data to
  results of this endpoint (requires a separate ADR)"* — this is that ADR.

The open item *"Provide a way to return different patterns of recommended purls"* is not
addressed here. The `trusted_source` flag designates an entire advisory feed as authoritative
(source-scoped), not a configurable per-pattern mechanism. Pattern-based recommendation
selection is deferred to a future decision.

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

[Lightwell](https://www.redhat.com/en/lightwell) publishes OSV advisories that explicitly encode the
remediation relationship between upstream and vendor packages. Each such advisory contains:

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

The system must distinguish advisory feeds that carry authoritative remediation data from
those that do not.

## Decision

### Trusted source designation via importer configuration

Introduce a `trusted_source: bool` field on the importer configuration model (default:
`false`). This field designates an advisory feed as carrying authoritative remediation data.
When `true`, the ingestor extracts recommendation records from the feed's advisories at
ingest time.

The flag is also exposed on the manual advisory upload endpoint (admin-gated), allowing
operators to mark individual advisory uploads as trusted sources.

The decision to designate a feed as a trusted source is a deployment-time operator
decision, not a heuristic. The flag is not inferred automatically.

### Ingest-time recommendation extraction

For each OSV advisory ingested from a trusted source, the ingestor hook:

1. Checks `database_specific.backport_base_version` — if absent, skips the advisory.
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

### Recommendation entity schema

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
coverage from other authoritative sources, and re-process advisories to refresh recommendations.

### Query integration via DB JOIN

Recommendation data is served to consumers via database JOIN rather than by calling
the existing `/purl/recommend` endpoint. Any query that needs to present recommendation
data (vulnerability analysis, SBOM analysis, package detail views) joins the
`recommendation` table directly. This means:

* Zero per-row or per-page overhead — no secondary endpoint calls in response handlers.
* Consistent data — all consumers read from the same source of truth.
* No dependency on the heuristic endpoint's runtime behavior.

### Backward compatibility

The existing `/purl/recommend` heuristic endpoint remains unchanged. Deployments that
have not ingested trusted-source advisories continue to function as before. The endpoint
can be deprecated in a future release once recommendation data is available via the DB
JOIN path and operators have migrated to trusted-source advisory feeds.

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
already encodes the answer; reading it is strictly more accurate.

### Per-query heuristic evaluation

Continue using the `/purl/recommend` endpoint at query time, calling it per-row or
per-page from response handlers.

**Why not chosen:** Per-query calls to a secondary endpoint add latency proportional to
the result set size. DB JOINs on pre-computed recommendation records have constant
overhead regardless of result set size. The heuristic endpoint also has the accuracy
limitations described above.

## Consequences

* Recommendation data is ecosystem-agnostic: any package covered by an OSV advisory that
  includes `backport_base_version` is eligible, regardless of vendor or versioning scheme.
* Zero per-query overhead for recommendation data in any consuming view — all reads are
  DB JOINs on the `recommendation` table.
* Recommendation records carry full provenance via the advisory foreign key, enabling
  audit, retraction, and re-computation.
* Recommendations only appear for packages covered by a trusted-source advisory that has
  been ingested. Deployments without trusted-source advisory feeds configured will have no
  recommendation records (the existing `/purl/recommend` heuristic continues to serve those
  deployments).
* The existing `/purl/recommend` endpoint is unchanged and remains the fallback for
  deployments not using trusted-source advisory feeds. It can be deprecated in a future
  version.
* A re-index endpoint allows operators to populate recommendation records from
  already-ingested trusted-source advisories without re-fetching from the source.
