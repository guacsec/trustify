//! Explicit, fixed-workload measurements of the production ingestion/extraction/verdict pipeline.
//! See `docs/correlation-performance.md` for running and comparing measurements.

#![recursion_limit = "512"]

use anyhow::{Context, ensure};
use rstest::rstest;
use sea_orm::{ConnectionTrait, DatabaseConnection, FromQueryResult, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env::{
        self,
        consts::{ARCH, OS},
    },
    fs::OpenOptions,
    io::Write,
    process::Command,
    time::Instant,
};
use test_context::test_context;
use trustify_common::db::{self, sql};
use trustify_module_correlation::{
    extractor::Extractors,
    service::{extraction, freshness, projection, tuning::WorkerConfig},
};
use trustify_test_context::{TrustifyContext, document_bytes};
use uuid::Uuid;

/// Change the version whenever generated documents or measurement boundaries change.
const WORKLOAD_VERSION: u32 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Workload {
    sboms: usize,
    packages: usize,
    advisory_pairs: usize,
    targets_per_advisory: usize,
}

impl Default for Workload {
    fn default() -> Self {
        Self {
            sboms: 60,
            packages: 1000,
            advisory_pairs: 500,
            targets_per_advisory: 20,
        }
    }
}

impl Workload {
    fn from_env() -> anyhow::Result<Self> {
        let workload: Self = match env::var("CORRELATION_BENCH_CONFIG") {
            Ok(value) => serde_json::from_str(&value).context("CORRELATION_BENCH_CONFIG")?,
            Err(env::VarError::NotPresent) => Self::default(),
            Err(err) => return Err(err.into()),
        };
        ensure!(
            workload.sboms > 0 && workload.packages > 0 && workload.advisory_pairs > 0,
            "SBOM, package and advisory pair counts must be positive"
        );
        ensure!(
            (1..=workload.packages).contains(&workload.targets_per_advisory),
            "targets_per_advisory must be between 1 and packages"
        );
        Ok(workload)
    }

    fn verdicts(&self) -> usize {
        self.sboms * self.advisory_pairs * self.targets_per_advisory
    }
}

struct Documents {
    sboms: Vec<Vec<u8>>,
    advisories: Vec<Vec<u8>>,
}

impl Documents {
    async fn generate(workload: &Workload) -> anyhow::Result<Self> {
        let template: Value = serde_json::from_slice(
            &document_bytes("csaf/issues/2740/variant-full_product_names.json").await?,
        )?;
        let components = (0..workload.packages)
            .map(|package| {
                json!({
                    "type": "library", "name": format!("bench-{package}"),
                    "version": "1.0.0", "bom-ref": format!("package-{package}"),
                    "purl": format!("pkg:cargo/bench-{package}@1.0.0")
                })
            })
            .collect::<Vec<_>>();
        let dependencies = (0..workload.packages)
            .map(|package| format!("package-{package}"))
            .collect::<Vec<_>>();
        let mut sboms = Vec::new();
        for index in 0..workload.sboms {
            let serial = Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                format!("correlation-bench-{index}").as_bytes(),
            );
            sboms.push(serde_json::to_vec(&json!({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "serialNumber": format!("urn:uuid:{serial}"),
                "metadata": {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "component": {"type": "application", "name": format!("app-{index}"),
                                  "version": "1.0.0", "bom-ref": "root"}
                },
                "components": components,
                "dependencies": [{"ref": "root", "dependsOn": dependencies}]
            }))?);
        }
        let mut advisories = Vec::new();
        for index in 0..workload.advisory_pairs {
            let cve = format!("CVE-2099-{:05}", index + 10000);
            let packages = (0..workload.targets_per_advisory)
                .map(|offset| (index * workload.targets_per_advisory + offset) % workload.packages)
                .collect::<Vec<_>>();
            let products = packages
                .iter()
                .map(|package| format!("package-{package}"))
                .collect::<Vec<_>>();
            let mut csaf = template.clone();
            csaf["document"]["tracking"]["id"] = json!(format!("BENCH-CSAF-{index:05}"));
            csaf["product_tree"] = json!({"full_product_names": packages.iter().map(|package| json!({
                "name": format!("bench-{package} 1.0.0"), "product_id": format!("package-{package}"),
                "product_identification_helper": {"purl": format!("pkg:cargo/bench-{package}@1.0.0")}
            })).collect::<Vec<_>>()});
            csaf["vulnerabilities"] = json!([{
                "cve": cve,
                "notes": [{"category": "description", "text": "Benchmark vulnerability"}],
                "product_status": {"known_affected": products},
                "remediations": [{"category": "mitigation", "details": "Benchmark mitigation",
                                  "product_ids": products}]
            }]);
            advisories.push(serde_json::to_vec(&csaf)?);
            advisories.push(serde_json::to_vec(&json!({
                "id": format!("BENCH-OSV-{index:05}"), "aliases": [cve],
                "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
                "summary": "Benchmark vulnerability",
                "affected": packages.iter().map(|package| json!({
                    "package": {"ecosystem": "crates.io", "name": format!("bench-{package}"),
                                "purl": format!("pkg:cargo/bench-{package}")},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
                })).collect::<Vec<_>>()
            }))?);
        }
        Ok(Self { sboms, advisories })
    }
}

#[derive(Serialize)]
struct Measurement {
    stage: &'static str,
    seconds: f64,
    units: usize,
    unit: &'static str,
    units_per_second: f64,
}

fn measure(stage: &'static str, start: Instant, units: usize, unit: &'static str) -> Measurement {
    let seconds = start.elapsed().as_secs_f64();
    eprintln!("{stage}: {seconds:.3}s ({units} units)");
    Measurement {
        stage,
        seconds,
        units,
        unit,
        units_per_second: units as f64 / seconds,
    }
}

async fn ingest(ctx: &TrustifyContext, documents: &[Vec<u8>]) -> anyhow::Result<()> {
    for document in documents {
        ctx.ingest_read(document.as_slice()).await?;
    }
    Ok(())
}

async fn extract(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let db = db::ReadWrite::new(ctx.db.clone());
    let config = WorkerConfig::default();
    let connection: &DatabaseConnection = &ctx.db;
    let extractors = Extractors::default()
        .with_match_batch(config.match_batch)
        .with_detail_connection(connection.clone());
    while extraction::run_step(&db, &extractors, &config).await? {}
    while freshness::run_step(&db, &extractors, &config).await? {}
    let tx = ctx.db.begin().await?;
    let state = freshness::overview(&tx).await?;
    ensure!(
        state.needs_refresh == 0,
        "incomplete SBOM extraction: {state:?}"
    );
    let lag = extraction::lag(&tx).await?;
    ensure!(
        lag.pending_advisories == 0 && lag.failed == 0,
        "incomplete advisory extraction: {lag:?}"
    );
    ensure!(
        state.latest_job.is_none_or(|job| job.failed == 0),
        "refresh job failed"
    );
    Ok(())
}

async fn count(ctx: &TrustifyContext, statement: &str) -> anyhow::Result<i64> {
    Ok(ctx
        .db
        .query_one_raw(sql(statement, []))
        .await?
        .context("missing count")?
        .try_get_by_index(0)?)
}

#[derive(Serialize, FromQueryResult)]
struct TableStorage {
    table_name: String,
    rows: i64,
    /// Includes TOAST data/indexes and the table's auxiliary forks.
    table_bytes: i64,
    index_bytes: i64,
    total_bytes: i64,
}

// Static statements also work on revisions without the two shared detail tables.
const EVIDENCE_TABLES: [(&str, &str, &str); 4] = [
    (
        "correlation_evidence",
        "SELECT count(*) FROM correlation_evidence",
        "VACUUM (FULL, ANALYZE) correlation_evidence",
    ),
    (
        "correlation_evidence_context",
        "SELECT count(*) FROM correlation_evidence_context",
        "VACUUM (FULL, ANALYZE) correlation_evidence_context",
    ),
    (
        "correlation_matched_value",
        "SELECT count(*) FROM correlation_matched_value",
        "VACUUM (FULL, ANALYZE) correlation_matched_value",
    ),
    (
        "correlation_confidence_factors",
        "SELECT count(*) FROM correlation_confidence_factors",
        "VACUUM (FULL, ANALYZE) correlation_confidence_factors",
    ),
];

async fn table_storage(ctx: &TrustifyContext) -> anyhow::Result<Vec<TableStorage>> {
    let mut tables = ctx
        .db
        .query_all_raw(sql(
            "SELECT c.relname::text AS table_name, 0::bigint AS rows, \
             pg_table_size(c.oid) AS table_bytes, pg_indexes_size(c.oid) AS index_bytes, \
             pg_total_relation_size(c.oid) AS total_bytes \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = current_schema() AND c.relkind = 'r' \
             AND c.relname = ANY($1::text[]) ORDER BY c.relname",
            [EVIDENCE_TABLES
                .iter()
                .map(|(name, _, _)| name.to_string())
                .collect::<Vec<_>>()
                .into()],
        ))
        .await?
        .iter()
        .map(|row| TableStorage::from_query_result(row, ""))
        .collect::<Result<Vec<_>, _>>()?;
    for (name, statement, _) in EVIDENCE_TABLES {
        if let Some(table) = tables.iter_mut().find(|table| table.table_name == name) {
            table.rows = count(ctx, statement).await?;
        }
    }
    ensure!(
        tables
            .iter()
            .any(|table| table.table_name == "correlation_evidence"),
        "missing evidence table"
    );
    Ok(tables)
}

async fn evidence_storage(ctx: &TrustifyContext) -> anyhow::Result<Value> {
    let as_loaded = table_storage(ctx).await?;
    let compact = match env::var("CORRELATION_BENCH_COMPACT_STORAGE") {
        Ok(value) => value
            .parse::<bool>()
            .context("CORRELATION_BENCH_COMPACT_STORAGE must be true or false")?,
        Err(env::VarError::NotPresent) => false,
        Err(err) => return Err(err.into()),
    };
    let compacted = if compact {
        // Only this test's disposable embedded database is affected, after all timed work.
        for (name, _, statement) in EVIDENCE_TABLES {
            if as_loaded.iter().any(|table| table.table_name == name) {
                ctx.db.execute_unprepared(statement).await?;
            }
        }
        Some(table_storage(ctx).await?)
    } else {
        None
    };
    let total = |tables: &[TableStorage]| tables.iter().map(|table| table.total_bytes).sum::<i64>();
    Ok(json!({
        "as_loaded_total_bytes": total(&as_loaded),
        "compacted_total_bytes": compacted.as_deref().map(total),
        "as_loaded": as_loaded,
        "compacted": compacted,
    }))
}

fn command_output(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(output.status.success(), "{program} {args:?} failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Each case gets a fresh database, fixed document bytes, and a single production worker.
#[test_context(TrustifyContext)]
#[rstest]
#[case::sboms_first(true)]
#[case::advisories_first(false)]
#[test_log::test(tokio::test)]
#[ignore = "explicit multi-minute correlation pipeline benchmark"]
async fn correlation_pipeline(
    ctx: &TrustifyContext,
    #[case] sboms_first: bool,
) -> anyhow::Result<()> {
    ensure!(!cfg!(debug_assertions), "run this benchmark with --release");
    ensure!(
        env::var_os("EXTERNAL_TEST_DB").is_none(),
        "benchmark requires isolated embedded PostgreSQL"
    );
    let workload = Workload::from_env()?;
    let documents = Documents::generate(&workload).await?;
    let scenario = if sboms_first {
        "sboms_first"
    } else {
        "advisories_first"
    };
    let db_version: String = ctx
        .db
        .query_one_raw(sql("SELECT version()", []))
        .await?
        .context("missing PostgreSQL version")?
        .try_get_by_index(0)?;
    let db_settings: Value = ctx.db.query_one_raw(sql(
        "SELECT jsonb_object_agg(name, jsonb_build_object('value', setting, 'unit', unit)) FROM pg_settings WHERE name IN ('work_mem', 'shared_buffers', 'max_wal_size', 'checkpoint_timeout', 'jit', 'synchronous_commit', 'max_parallel_workers_per_gather')",
        [],
    )).await?.context("missing PostgreSQL settings")?.try_get_by_index(0)?;
    let (first, second) = if sboms_first {
        (&documents.sboms, &documents.advisories)
    } else {
        (&documents.advisories, &documents.sboms)
    };
    let start = Instant::now();
    let mut measurements = Vec::new();
    eprintln!("Starting {scenario}: {}", serde_json::to_string(&workload)?);
    let stage = Instant::now();
    ingest(ctx, first).await?;
    measurements.push(measure("ingest_initial", stage, first.len(), "documents"));
    let stage = Instant::now();
    extract(ctx).await?;
    measurements.push(measure("extract_initial", stage, first.len(), "documents"));
    let stage = Instant::now();
    ingest(ctx, second).await?;
    measurements.push(measure(
        "ingest_incremental",
        stage,
        second.len(),
        "documents",
    ));
    let stage = Instant::now();
    extract(ctx).await?;
    measurements.push(measure(
        "extract_incremental",
        stage,
        workload.verdicts() * 2,
        "evidence",
    ));
    let stage = Instant::now();
    let db = db::ReadWrite::new(ctx.db.clone());
    let config = WorkerConfig::default();
    while projection::run_step(&db, &config).await? {}
    measurements.push(measure("verdict", stage, workload.verdicts(), "verdicts"));
    let elapsed = start.elapsed();

    // Fewer outputs or failed/deferred work must never look like an improvement.
    let evidence = count(ctx, "SELECT count(*) FROM correlation_evidence").await?;
    let verdicts = count(ctx, "SELECT count(*) FROM correlation_verdict").await?;
    ensure!(
        evidence == i64::try_from(workload.verdicts() * 2)?,
        "unexpected evidence count: {evidence}"
    );
    ensure!(
        verdicts == i64::try_from(workload.verdicts())?,
        "unexpected verdict count: {verdicts}"
    );
    let tx = ctx.db.begin().await?;
    let lag = projection::lag(&tx).await?;
    ensure!(
        lag.pending == 0 && lag.failed == 0,
        "incomplete verdict publication: {lag:?}"
    );
    tx.rollback().await?;
    let storage = evidence_storage(ctx).await?;
    eprintln!(
        "Evidence storage: {} bytes including indexes and shared detail tables",
        storage["as_loaded_total_bytes"]
    );
    let report = json!({
        "workload_version": WORKLOAD_VERSION, "scenario": scenario, "workload": workload,
        "git_commit": command_output("git", &["rev-parse", "HEAD"] )?,
        "git_dirty": !command_output("git", &["status", "--porcelain"])?.is_empty(),
        "rustc": command_output("rustc", &["--version"] )?, "os": OS, "arch": ARCH,
        "machine": env::var("CORRELATION_BENCH_MACHINE").ok(),
        "postgres": db_version, "postgres_settings": db_settings,
        "profile": "release", "workers": config.workers.get(),
        "match_batch": config.match_batch,
        "ingestion_seconds": measurements.iter().filter(|m| m.stage.starts_with("ingest_")).map(|m| m.seconds).sum::<f64>(),
        "extraction_seconds": measurements.iter().filter(|m| m.stage.starts_with("extract_")).map(|m| m.seconds).sum::<f64>(),
        "total_seconds": elapsed.as_secs_f64(), "measurements": measurements,
        "evidence": evidence, "verdicts": verdicts,
        "evidence_storage": storage,
        "timestamp": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    let report = serde_json::to_string(&report)?;
    println!("\nCORRELATION_BENCH_RESULT {report}");
    if let Some(path) = env::var_os("CORRELATION_BENCH_OUTPUT") {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{report}")?;
    }
    Ok(())
}
