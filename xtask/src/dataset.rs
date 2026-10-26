use anyhow::{Context as _, anyhow};
use bytes::Bytes;
use clap::Parser;
use postgresql_commands::{CommandBuilder, CommandExecutor, pg_dump::PgDumpBuilder};
use postgresql_embedded::Settings;
use serde_json::Value;
use std::{
    env,
    fs::create_dir_all,
    io::BufReader,
    path::PathBuf,
    time::{Duration, Instant},
};
use tar::Builder;
use tempfile::TempDir;
use tokio::fs;
use trustify_common::{db::ReadWrite, model::BinaryByteSize};
use trustify_db::embedded;
use trustify_module_correlation::{
    extractor::Extractors, model::ExtractionLag, service::extraction,
};
use trustify_module_importer::{
    model::{
        CommonImporter, CsafImporter, CveImporter, ImporterConfiguration, SbomImporter,
        auth::CredentialConfig,
    },
    runner::{
        ImportRunner,
        context::RunContext,
        progress::{Progress, TracingProgress},
    },
};
use trustify_module_ingestor::{
    graph::Graph,
    service::{Cache, Format, IngestorService},
};
use trustify_module_storage::service::{Compression, fs::FileSystemBackend};
use walker_common::compression::Detector;

#[derive(Debug, Parser)]
pub struct GenerateDump {
    /// The name of the output dump file
    #[arg(short, long, default_value = "dump.sql")]
    output: PathBuf,

    /// The name of the output storage dump file
    #[arg(short, long)]
    storage_output: Option<PathBuf>,

    /// The name of the input configuration. Uses a default configuration if missing.
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// An optional specified working directory, which is kept after the run.
    ///
    /// Defaults to a temporary directory in Cargo's target directory, or the system's
    /// temporary directory when not running through Cargo.
    #[arg(short, long, env = "GENERATE_DUMP_WORKING_DIR")]
    working_dir: Option<PathBuf>,

    /// Files greater than this limit will be ignored.
    #[arg(long)]
    size_limit: Option<BinaryByteSize>,

    /// Number of times to retry fetching a document.
    #[arg(long, conflicts_with = "input")]
    fetch_retries: Option<usize>,

    /// Skip correlation extraction before writing the dump.
    #[arg(long)]
    no_correlation: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct Instructions {
    /// importer configurations to run
    #[serde(default)]
    import: Vec<ImporterConfiguration>,

    /// Files or directories to scan and import
    #[serde(default)]
    paths: Vec<PathBuf>,
}

impl GenerateDump {
    fn load_config(&self) -> anyhow::Result<(PathBuf, Instructions)> {
        match &self.input {
            Some(input) => {
                let mut path = input.clone();
                path.pop();
                Ok((
                    path,
                    serde_saphyr::from_reader(BufReader::new(std::fs::File::open(input)?))?,
                ))
            }
            None => {
                let import = vec![
                    ImporterConfiguration::Cve(CveImporter {
                        common: default_common("CVEs starting 2024"),
                        source: "https://github.com/CVEProject/cvelistV5".to_string(),
                        years: Default::default(),
                        start_year: Some(2024),
                    }),
                    ImporterConfiguration::Sbom(SbomImporter {
                        common: default_common("All Red Hat SBOMs"),
                        source: "https://security.access.redhat.com/data/sbom/v1/".to_string(),
                        keys: vec!["https://security.access.redhat.com/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4".parse()?],
                        v3_signatures: true,
                        only_patterns: vec![],
                        size_limit: self.size_limit,
                        fetch_retries: self.fetch_retries,
                        ignore_missing: false,
                    }),
                    ImporterConfiguration::Csaf(CsafImporter {
                        common: default_common("Red Hat VEX documents from 2024"),
                        source: "redhat.com".to_string(),
                        v3_signatures: true,
                        only_patterns: vec!["^cve-2024-".into()],
                        fetch_retries: self.fetch_retries,
                        ignore_missing: false,
                    })
                ];

                let path = env::current_dir()?;

                Ok((
                    path,
                    Instructions {
                        import,
                        paths: vec![],
                    },
                ))
            }
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        // Without a working directory, prefer a temporary one below the target directory
        // over /tmp, which may be a size-limited tmpfs.
        let (wd, _tmp) = match &self.working_dir {
            Some(wd) => (wd.clone(), None),
            None => {
                let tmp = temp_working_dir()?;
                tracing::info!(
                    "Using temporary working directory: {}",
                    tmp.path().display()
                );
                (tmp.path().to_owned(), Some(tmp))
            }
        };

        let storage_path = wd.join("storage");
        let storage = FileSystemBackend::new(&storage_path, Compression::Zstd).await?;

        let migrator = trustify_db::Migrator::new(storage.clone(), ());

        let (db, postgres) = match &self.working_dir {
            Some(wd) => embedded::create_in(wd.join("db"), &migrator).await?,
            // Keep using the shared PostgreSQL installation, only move the data.
            None => {
                let settings = Settings {
                    data_dir: wd.join("db"),
                    ..embedded::default_settings()?
                };
                embedded::create_for(settings, Default::default(), &migrator).await?
            }
        };

        let importer = ImportRunner {
            db: ReadWrite::new(db.clone()),
            storage: storage.into(),
            working_dir: Some(wd.join("wd")),
            // The xtask doesn't need the analysis graph
            analysis: None,
            credential_config: CredentialConfig::default(),
        };

        // ingest documents

        let start = Instant::now();
        self.ingest(importer).await?;
        let ingestion = start.elapsed();

        let extraction = if self.no_correlation {
            None
        } else {
            tracing::info!("Extracting correlation evidence before dumping");
            let start = Instant::now();
            let db_rw = ReadWrite::new(db.clone());
            let extractors = Extractors::default();
            let mut events = 0u64;
            while extraction::run_step(&db_rw, &extractors).await? {
                events += 1;
            }
            let elapsed = start.elapsed();

            // Failed extractions stay queued for retry. Do not export a dump
            // advertised as correlated while some ingestion work is unfinished.
            let lag = db_rw
                .transaction(async |tx| extraction::lag(tx).await)
                .await?;
            anyhow::ensure!(
                lag == ExtractionLag::default(),
                "Correlation extraction is incomplete: {} advisory changes and {} SBOM changes pending ({} failed)",
                lag.pending_advisories,
                lag.pending_sboms,
                lag.failed,
            );
            let rate = match elapsed.as_secs_f64() {
                secs if secs > 0.0 => events as f64 / secs,
                _ => 0.0,
            };
            tracing::info!(
                "Correlation extraction complete: {events} events in {elapsed:?} ({rate:.1} events/s)"
            );
            Some(elapsed)
        };

        // create DB dump

        let start = Instant::now();

        let settings = postgres.settings();
        let mut pg_dump = PgDumpBuilder::from(settings)
            .dbname(db.name())
            .file(&self.output)
            .build();
        let (stdout, stderr) = pg_dump.execute()?;

        tracing::debug!("stdout: {stdout}");
        tracing::debug!("stderr: {stderr}");
        tracing::info!("Dumped to: {}", self.output.display());

        // create storage dump

        if let Some(file) = self.storage_output {
            let tar = std::fs::File::create(&file)?;
            let mut tar = Builder::new(tar);
            tar.append_dir_all(".", storage_path)?;
            drop(tar);

            tracing::info!("Dumped storage to: {}", file.display());
        }

        let dump = start.elapsed();

        // done

        let extraction = extraction
            .map(|elapsed| format!("{elapsed:?}"))
            .unwrap_or_else(|| "skipped".into());
        tracing::info!(
            "Timings: ingestion {ingestion:?}, correlation extraction {extraction}, dump {dump:?}"
        );

        Ok(())
    }

    async fn ingest(&self, runner: ImportRunner) -> anyhow::Result<()> {
        let (wd, config) = self.load_config()?;

        // run importers

        for run in config.import {
            let description = run
                .description
                .clone()
                .unwrap_or_else(|| "<unnamed>".into());
            tracing::info!("Ingesting: {description}");

            let start = Instant::now();
            self.ingest_one(&runner, run).await?;
            tracing::info!("Ingested {description} in {:?}", start.elapsed());
        }

        // ingest files

        let service = IngestorService::new(Graph::new(), runner.storage.clone(), None);
        for path in config.paths {
            let name = path.display().to_string();
            tracing::info!("Ingesting: {name}");
            let start = Instant::now();
            let path = wd.join(path);
            let path = path
                .canonicalize()
                .with_context(|| format!("failed to canonicalize '{}'", path.display()))?;
            tracing::info!(" Resolved: {}", path.display());

            let mut files = vec![];

            if path.is_dir() {
                for entry in walkdir::WalkDir::new(path).follow_links(true) {
                    let entry = entry?;
                    if !entry.file_type().is_file() {
                        continue;
                    }
                    if entry.file_name().to_string_lossy().starts_with(".") {
                        continue;
                    }
                    files.push(entry.into_path());
                }
            } else {
                files.push(path);
            }

            for file in files {
                let name = file.as_os_str().to_string_lossy().to_string();

                tracing::info!("Loading: {name}");
                let data: Bytes = fs::read(file).await?.into();

                let detector = Detector {
                    file_name: Some(name.as_str()),
                    ..Default::default()
                };
                let data = detector
                    .decompress(data)
                    .map_err(|err| anyhow!("{err}"))
                    .with_context(|| format!("failed to decompress: '{name}'"))?;

                let result = runner
                    .db
                    .transaction(async |tx| {
                        service
                            .ingest(&data, Format::Unknown, (), None, Cache::Skip, tx)
                            .await
                    })
                    .await?;
                tracing::info!("  id: {}", result.id);
                if !result.warnings.is_empty() {
                    tracing::warn!("  warnings:");
                    for warning in result.warnings {
                        tracing::warn!("    - {}", warning);
                    }
                }
            }

            tracing::info!("Ingested {name} in {:?}", start.elapsed());
        }

        // done

        tracing::info!("Done ingesting");

        Ok(())
    }

    async fn ingest_one(
        &self,
        runner: &ImportRunner,
        configuration: ImporterConfiguration,
    ) -> anyhow::Result<()> {
        runner
            .run_once(
                Context {
                    name: "run".to_string(),
                },
                configuration,
                None,
                Value::Null,
            )
            .await?;

        Ok(())
    }
}

/// Create a temporary working directory in Cargo's target directory, or the system's
/// temporary directory when not running through Cargo.
fn temp_working_dir() -> anyhow::Result<TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("generate-dump-");

    Ok(match target_dir() {
        Some(target) => {
            create_dir_all(&target)?;
            builder.tempdir_in(target)?
        }
        None => builder.tempdir()?,
    })
}

/// Cargo's target directory, if running through Cargo.
///
/// Cargo doesn't pass the target directory to the binaries it runs, so this uses an
/// explicit `CARGO_TARGET_DIR`, or the default one in the workspace root, which
/// `.cargo/config.toml` provides as `CARGO_WORKSPACE_ROOT`.
fn target_dir() -> Option<PathBuf> {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("CARGO_WORKSPACE_ROOT").map(|root| PathBuf::from(root).join("target"))
        })
}

fn default_common(description: impl Into<String>) -> CommonImporter {
    CommonImporter {
        disabled: false,
        period: Default::default(),
        description: Some(description.into()),
        labels: Default::default(),
    }
}

#[derive(Debug)]
struct Context {
    name: String,
}

impl RunContext for Context {
    fn name(&self) -> &str {
        &self.name
    }

    async fn is_canceled(&self) -> bool {
        // for generating the dump, we don't cancel
        false
    }

    fn progress(&self, message: String) -> impl Progress + 'static {
        TracingProgress {
            name: format!("{}: {message}", self.name),
            period: Duration::from_secs(15),
        }
    }
}
