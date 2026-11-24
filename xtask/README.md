# Dataset dump generation

`cargo xtask generate-dump` imports documents into embedded PostgreSQL, extracts
correlation evidence, and writes a SQL dump. Use `--help` for all options.

```sh
cargo xtask generate-dump \
  --correlation-work-mem 256MiB \
  --correlation-workers 4 \
  --correlation-match-batch 100000 \
  --pg-setting max_wal_size=4GB \
  --pg-setting shared_buffers=512MB
```

Correlation uses the same options and environment variables as the API server and
worker:

| Option | Environment variable | Default |
| --- | --- | --- |
| `--correlation-work-mem` | `TRUSTD_CORRELATION_WORK_MEM` | PostgreSQL's setting |
| `--correlation-workers` | `TRUSTD_CORRELATION_WORKERS` | `1`; `0` selects available CPU parallelism |
| `--correlation-match-batch` | `TRUSTD_CORRELATION_MATCH_BATCH` | `100000` |

Work memory applies per PostgreSQL sort or hash operation inside worker
transactions, so each worker can use more than the configured amount. Increasing
the worker count can increase total memory consumption. The match batch bounds
the matches held before writing evidence; a single node's matches can exceed it.

Repeat `--pg-setting NAME=VALUE` to configure embedded PostgreSQL before startup.
Alternatively, set `TRUSTD_EMBEDDED_PG_SETTINGS` to comma-separated assignments:

```sh
TRUSTD_EMBEDDED_PG_SETTINGS='max_wal_size=4GB,shared_buffers=512MB' \
  cargo xtask generate-dump
```

CLI assignments replace the environment variable's entire list. Within a list,
the last assignment for each name wins. PostgreSQL validates setting names and
values. Overrides apply with or without `--working-dir`; omitting them preserves
the existing database defaults.

All correlation workers finish before export, and unfinished extraction prevents
the dump. Use `--no-correlation` to skip extraction.
