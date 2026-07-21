# correlate_purls: product_by_name dedup bug

## Status

The `correlate_purls` product_by_name lookup is implemented and working, but the
`analyze_vulnerability_ids_match_sql` correctness test still fails because of a
dedup bug.

## What was done

* `PurlCorrelationMatch` fields made optional (`purl_status_id`, `product_status_id`,
  `version_range`) to support both purl_status and product_status match sources
* `correlate_purls` now queries `AdvisoryIndex.product_by_name` after the existing
  `by_purl` loop, using bare name and `namespace/name` as lookup keys
* All three hydration functions (`hydrate_analysis`, `hydrate_purl_advisories`,
  `hydrate_recommend_matches`) updated for the optional fields
* Correctness tests updated to hard equality assertions (no more subset checks)

## Passing tests

* `sbom_advisory_count_matches_sql` (22 advisories for quarkus-bom)
* `vulnerability_advisory_count_matches_sql` (CVE-2023-4853)
* `purl_advisory_count_matches_sql` (CVE-2023-0044 now found)
* `recommend_returns_results`
* `sbom_ubi8_advisory_count_matches_sql` (1 advisory for ubi8)

## Failing test

* `analyze_vulnerability_ids_match_sql` -- missing CVE-2023-0044

## Root cause

In `modules/correlation/src/service/mod.rs`, the `correlate_purls` method deduplicates
product_by_name matches against existing by_purl matches using a `HashSet<(Uuid, Arc<str>)>`
keyed on `(advisory_id, vulnerability_id)`.

The CSAF document for CVE-2023-0044 (`etc/datasets/ds3/csaf/2023/cve-2023-0044.json`)
contains BOTH:
* `known_not_affected` entries for `quarkus-vertx-http` (matched via by_purl as purl_status)
* `known_affected` entries for `quarkus-vertx-http` (matched via product_by_name as product_status)

The by_purl loop runs first and inserts `(advisory_id, CVE-2023-0044)` into `seen` with
`not_affected` status. When the product_by_name loop encounters the `affected` entry for
the same `(advisory_id, CVE-2023-0044)`, it's already in `seen` and gets skipped.

Later, `hydrate_analysis` (line 384-386) filters to only `affected` and
`under_investigation` statuses, so the `not_affected` entry is dropped -- and the
`affected` entry was never added.

Debug tracing confirmed this: CVE-2023-0044 shows `is_new=true` in the purl test (which
doesn't go through hydrate_analysis filtering), but in the analyze test the affected entry
is blocked by the dedup.

## Fix

Change the dedup key from `(advisory_id, vulnerability_id)` to
`(advisory_id, vulnerability_id, status_id)` so that different statuses for the same
advisory+CVE pair are not collapsed. This is on line 263 of `service/mod.rs`:

```rust
// Current (broken):
let mut seen: HashSet<(Uuid, Arc<str>)> = matches
    .iter()
    .map(|m| (m.advisory_id, Arc::clone(&m.vulnerability_id)))
    .collect();

// Fix:
let mut seen: HashSet<(Uuid, Arc<str>, Uuid)> = matches
    .iter()
    .map(|m| (m.advisory_id, Arc::clone(&m.vulnerability_id), m.status_id))
    .collect();
```

And update the `seen.insert()` call on line 271 to include `entry.status_id`:

```rust
let is_new = seen.insert((
    entry.advisory_id,
    Arc::clone(&entry.vulnerability_id),
    entry.status_id,
));
```

## Cleanup needed after fix

* Remove the temporary `tracing::debug!` block in `correlate_purls` (lines 275-281)
* Run `cargo xtask precommit`
* All 6 correctness tests should pass
