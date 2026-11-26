# Correlation performance measurements

`modules/correlation/tests/performance.rs` is an ignored integration benchmark of
the production ingestion, durable extraction, and verdict publication services.
It uses a fresh embedded PostgreSQL database for each scenario. It needs no server,
downloaded advisory dataset, or existing database. The first build and PostgreSQL
installation may need network access.

## Run

Build first so compilation is separate from the measurement:

```sh
cargo test --release -p trustify-module-correlation --test performance --no-run
```

Run both scenarios sequentially and append their results to a JSON Lines file:

```sh
RUST_LOG=error CORRELATION_BENCH_OUTPUT=/tmp/correlation-results.jsonl \
  cargo test --release -p trustify-module-correlation --test performance \
  -- --ignored --nocapture --test-threads=1
```

The default workload targets a combined 5–10 minute run; actual duration depends on
the machine and database configuration. It performs fixed work, without sleeps or
time-based repetition. A faster implementation therefore finishes sooner.
Calibrate the dimensions once for your machine, then keep them unchanged when
comparing revisions.

Each scenario contains:

- 60 CycloneDX SBOMs, each with 1,000 distinct versioned Cargo packages.
- 500 CSAF/OSV advisory pairs: two sources reporting the same CVE and targeting
  the same 20 packages. OSV uses version ranges; CSAF uses exact versions and
  includes remediation records.
- Exactly 1,200,000 persisted evidence rows and 600,000 published verdicts.

`sboms_first` classifies the SBOMs, then measures extraction of new advisories
against those SBOMs. `advisories_first` drains the initial advisory queue, then
measures extraction of new SBOMs against those advisories. Both end by computing
and publishing all verdicts, including their counts and remediation snapshots.

Filter to one direction when investigating that path:

```sh
RUST_LOG=error cargo test --release -p trustify-module-correlation \
  --test performance sboms_first -- --ignored --nocapture --test-threads=1
```

For a quick correctness check of both scenarios:

```sh
RUST_LOG=error \
CORRELATION_BENCH_CONFIG='{"sboms":2,"packages":20,"advisory_pairs":4,"targets_per_advisory":5}' \
  cargo test --release -p trustify-module-correlation --test performance \
  -- --ignored --nocapture --test-threads=1
```

`CORRELATION_BENCH_CONFIG` accepts any subset of those four fields, with defaults
for the rest. All counts must be positive and `targets_per_advisory` cannot exceed
`packages`. Scaling `sboms` changes the evidence and verdict counts linearly;
changing `packages` changes identifier cardinality and match density too.

## Timings and comparison

Each scenario prints a `CORRELATION_BENCH_RESULT` JSON record and optionally
appends the same record to `CORRELATION_BENCH_OUTPUT`. Records include the Git
commit, dirty state, compiler/OS/architecture, workload version and dimensions,
PostgreSQL version and settings, worker settings, verified output counts,
ingestion/extraction totals, total seconds, and stage timings:

| Stage | Work measured |
|---|---|
| `ingest_initial` | Ingest and commit the first set of documents |
| `extract_initial` | Drain its advisory extraction queue and SBOM refresh jobs |
| `ingest_incremental` | Ingest and commit the second set of documents |
| `extract_incremental` | Match, scope, deduplicate, and persist all evidence |
| `verdict` | Resolve evidence, serialize snapshots, and publish verdicts/counts |

Database setup/migrations and document generation happen before the timer. Output
count verification and writing the result happen after it. Service transaction
commits and extraction completion checks are included. No background worker runs
during ingestion; stage boundaries isolate the work that changed.

The benchmark checks exact evidence/verdict counts, empty queues, no failed refresh
jobs, and current verdicts. Failed or deferred work fails the benchmark instead of
producing a misleading successful timing. The separate manual performance
benchmarks remain ignored.

Extract a CSV for a spreadsheet or trend chart:

```sh
jq -r '[.git_commit, .scenario, .total_seconds,
        (.measurements[] | select(.stage == "ingest_initial") | .seconds),
        (.measurements[] | select(.stage == "extract_initial") | .seconds),
        (.measurements[] | select(.stage == "ingest_incremental") | .seconds),
        (.measurements[] | select(.stage == "extract_incremental") | .seconds),
        (.measurements[] | select(.stage == "verdict") | .seconds)] | @csv' \
  /tmp/correlation-results.jsonl
```

Columns are commit, scenario, total seconds, and the five stages in table order.
Compare the same scenario, workload version, dimensions, release profile,
PostgreSQL version, machine, and settings. Keep the machine otherwise idle and run
several repetitions; compare medians rather than treating a single timing as a
regression threshold. A fresh database is used each time, but OS filesystem caches
are not flushed. Keep results outside the repository to avoid marking it dirty.
Set `CORRELATION_BENCH_MACHINE` to a stable machine label when collecting results
from several machines; that label is included in every record.

This workload covers PURL matching, cross-source CVE grouping, shared evidence
details, and remediation snapshots. It does not measure CPE/digest matching, HTTP,
remote downloads, or contention between concurrent importers and workers. It uses
one worker and PostgreSQL's embedded-test settings, independently of Compose.
`EXTERNAL_TEST_DB` is rejected to keep the workload isolated.

When changing document generation or measurement boundaries, bump
`WORKLOAD_VERSION` and establish a new baseline. To measure an older revision,
carry the identical benchmark onto that revision; do not compare different
workload versions as an implementation speedup.
