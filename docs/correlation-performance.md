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

## Evidence storage

Every result includes `evidence_storage`: per-table row counts and PostgreSQL
allocated sizes, plus their combined total. This includes `correlation_evidence`,
`correlation_evidence_context`, and, where present, `correlation_matched_value`
and `correlation_confidence_factors`. `table_bytes` includes TOAST storage and its
indexes; `index_bytes` counts the table's own indexes. `total_bytes` includes both.
Verdict snapshots and unrelated database tables are excluded.

For a before/after comparison, enable a second measurement after `VACUUM FULL`
rebuilds those tables and indexes:

```sh
RUST_LOG=error CORRELATION_BENCH_COMPACT_STORAGE=true \
CORRELATION_BENCH_OUTPUT=/tmp/correlation-storage.jsonl \
  cargo test --release -p trustify-module-correlation --test performance \
  advisories_first -- --ignored --nocapture --test-threads=1
```

This reports both as-loaded and compacted sizes for the same 1.2 million evidence
rows. Measurement and compaction run after the timed pipeline and validation, only
in the disposable embedded database. The generated workload and existing timing
boundaries are unchanged. Compare totals including all four tables; comparing only
`correlation_evidence` would omit the new tables' cost. The synthetic workload's
repetition determines the savings, so these figures are not a prediction for every
production dataset.

### Measured migration result

With the default workload's 1,200,000 evidence rows, PostgreSQL 17.2 on macOS
ARM64, applying `m0002740_correlation_evidence_details/up.sql` to the base
revision (`fae850832`) gave these sizes after compacting both layouts:

| Evidence storage | Before | After |
|---|---:|---:|
| Tables, including TOAST | 559.4 MiB | 276.3 MiB |
| Indexes | 93.4 MiB | 93.4 MiB |
| **Combined** | **652.8 MiB** | **369.7 MiB** |

The combined reduction was **43.4% (283.1 MiB)**, including the two new tables:
2,000 distinct matched values and one distinct set of confidence factors.
As-loaded sizes were 678.8 MiB before and 369.8 MiB after the migration.
The migration took 10.0 seconds in this run.

This comparison used the same database and evidence rows, not separately generated
datasets. The row count and sum of hashes of each row's canonical JSONB
representation matched before migration and through `correlation_evidence_detail`
after migration. Compaction and this integrity check ran outside pipeline timings.
These figures measure evidence storage, excluding verdict snapshots, WAL, and
temporary disk space needed while migrating.

When changing document generation or measurement boundaries, bump
`WORKLOAD_VERSION` and establish a new baseline. To measure an older revision,
carry the identical benchmark onto that revision; do not compare different
workload versions as an implementation speedup.
