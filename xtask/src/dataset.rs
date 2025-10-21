use anyhow::anyhow;
use bytes::Bytes;
use clap::Parser;
use postgresql_commands::{CommandBuilder, CommandExecutor, pg_dump::PgDumpBuilder};
use serde_json::Value;
use std::{env, io::BufReader, path::PathBuf, time::Duration};
use tar::Builder;
use tokio::fs;
use trustify_common::model::BinaryByteSize;
use trustify_module_importer::{
    model::{CommonImporter, CsafImporter, CveImporter, ImporterConfiguration, SbomImporter},
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

    /// An optional specified working directory
    #[arg(short, long)]
    working_dir: Option<PathBuf>,

    /// Files greater than this limit will be ignored.
    #[arg(long)]
    size_limit: Option<BinaryByteSize>,

    /// Number of times to retry fetching a document.
    #[arg(long, conflicts_with = "input")]
    fetch_retries: Option<usize>,
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
                    serde_yml::from_reader(BufReader::new(std::fs::File::open(input)?))?,
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
                        source: "https://access.redhat.com/security/data/sbom/beta/".to_string(),
                        keys: vec!["https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4".parse()?],
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
        let (db, postgres) = match &self.working_dir {
            Some(wd) => trustify_db::embedded::create_in(wd.join("db")).await?,
            None => trustify_db::embedded::create().await?,
        };

        let (storage, storage_path, _tmp) = match &self.working_dir {
            Some(wd) => (
                FileSystemBackend::new(wd.join("storage"), Compression::Zstd).await?,
                wd.clone(),
                None,
            ),
            None => {
                let (storage, tmp) = FileSystemBackend::for_test_with(Compression::Zstd).await?;
                (storage, tmp.path().to_owned(), Some(tmp))
            }
        };

        let importer = ImportRunner {
            db: db.clone(),
            storage: storage.into(),
            working_dir: self.working_dir.as_ref().map(|wd| wd.join("wd")),
            // The xtask doesn't need the analysis graph
            analysis: None,
        };

        // ingest documents

        self.ingest(importer).await?;

        // create DB dump

        let settings = postgres.settings();
        let mut pg_dump = PgDumpBuilder::from(settings)
            .dbname(db.name())
            .file(&self.output)
            .build();
        let (stdout, stderr) = pg_dump.execute()?;

        log::debug!("stdout: {stdout}");
        log::debug!("stderr: {stderr}");
        log::info!("Dumped to: {}", self.output.display());

        // create storage dump

        if let Some(file) = self.storage_output {
            let tar = std::fs::File::create(&file)?;
            let mut tar = Builder::new(tar);
            tar.append_dir_all(".", storage_path)?;
            drop(tar);

            log::info!("Dumped storage to: {}", file.display());
        }

        // done

        Ok(())
    }

    async fn ingest(&self, runner: ImportRunner) -> anyhow::Result<()> {
        let (wd, config) = self.load_config()?;

        // run importers

        for run in config.import {
            log::info!(
                "Ingesting: {}",
                run.description.as_deref().unwrap_or("<unnamed>")
            );

            self.ingest_one(&runner, run).await?;
        }

        // ingest files

        let service =
            IngestorService::new(Graph::new(runner.db.clone()), runner.storage.clone(), None);
        for path in config.paths {
            log::info!("Ingesting: {}", path.display());
            let path = wd.join(path).canonicalize()?;
            log::info!(" Resolved: {}", path.display());

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

                log::info!("Loading: {name}");
                let data: Bytes = fs::read(file).await?.into();

                let detector = Detector {
                    file_name: Some(name.as_str()),
                    ..Default::default()
                };
                let data = detector.decompress(data).map_err(|err| anyhow!("{err}"))?;

                let result = service
                    .ingest(&data, Format::Unknown, (), None, Cache::Skip)
                    .await?;
                log::info!("  id: {}", result.id);
                if !result.warnings.is_empty() {
                    log::warn!("  warnings:");
                    for warning in result.warnings {
                        log::warn!("    - {}", warning);
                    }
                }
            }
        }

        // done

        log::info!("Done ingesting");

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

    fn progress(&self, message: String) -> impl Progress + Send + 'static {
        TracingProgress {
            name: format!("{}: {message}", self.name),
            period: Duration::from_secs(15),
        }
    }
}
