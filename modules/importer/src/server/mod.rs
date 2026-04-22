pub mod context;
pub(crate) mod progress;

use crate::{
    model::{Importer, State},
    runner::{
        ImportRunner,
        common::heartbeat::Heart,
        report::{Report, ScannerError},
    },
    server::context::ServiceRunContext,
    service::{Error, ImporterService},
};
use opentelemetry::global;
use std::{path::PathBuf, time::Duration};
use time::OffsetDateTime;
use tokio::{task::LocalSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use trustify_common::db::{Database, pagination_cache::PaginationCache};
use trustify_module_analysis::service::AnalysisService;
use trustify_module_storage::service::dispatch::DispatchBackend;

/// Run the importer loop.
///
/// When `read_only` is true, the loop stays alive but no imports are started.
pub async fn importer(
    db: Database,
    cache: PaginationCache,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
    analysis: Option<AnalysisService>,
    concurrency: usize,
    read_only: bool,
) -> anyhow::Result<()> {
    Server {
        db,
        cache,
        storage,
        working_dir,
        analysis,
        concurrency,
        read_only,
    }
    .run()
    .await
}

#[derive(Clone, Debug)]
pub struct RunOutput {
    pub report: Report,
    pub continuation: Option<serde_json::Value>,
}

impl From<Report> for RunOutput {
    fn from(report: Report) -> Self {
        Self {
            report,
            continuation: None,
        }
    }
}

/// Single node, single process importer processor.
struct Server {
    db: Database,
    cache: PaginationCache,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
    analysis: Option<AnalysisService>,
    concurrency: usize,
    read_only: bool,
}

impl Server {
    #[instrument(skip_all, ret)]
    async fn run(self) -> anyhow::Result<()> {
        // The Heart struct spawns locally because the import fn isn't
        // Send, so we need a LocalSet
        LocalSet::new().run_until(self.run_local()).await
    }

    async fn run_local(self) -> anyhow::Result<()> {
        let meter = global::meter("importer::Server");
        let running_importers = meter.u64_gauge("running_importers").build();

        let service = ImporterService::new(self.db.clone(), self.cache.clone());
        let runner = ImportRunner {
            db: self.db.clone(),
            storage: self.storage.clone(),
            working_dir: self.working_dir.clone(),
            analysis: self.analysis.clone(),
        };
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Maintain a list of currently running jobs
        let mut runs: Vec<Heart> = Vec::new();

        loop {
            interval.tick().await;

            // Remove jobs that are finished; they're heartless ;)
            runs.retain(|heart| heart.is_beating());
            let count = runs.len();

            // Update metrics
            running_importers.record(count as _, &[]);

            let importers = service.list().await?;

            // Update any importers that we assume have crashed
            reap(&importers, &service).await?;

            // In read-only mode the loop stays alive for health probes but no imports are started
            if self.read_only {
                continue;
            }

            // Asynchronously fire off new jobs subject to max concurrency
            runs.extend(
                importers
                    .into_iter()
                    .filter(|i| i.is_enabled() && i.is_due() && !i.is_running())
                    .take(self.concurrency - count)
                    .map(|importer| {
                        let token = CancellationToken::new();
                        Heart::new(
                            importer.clone(),
                            runner.db.clone(),
                            import(runner.clone(), importer, service.clone(), token.clone()),
                            token,
                        )
                    }),
            );
        }
    }
}

async fn import(
    runner: ImportRunner,
    importer: Importer,
    service: ImporterService,
    cancel: CancellationToken,
) -> Result<(), Error> {
    log::debug!("  {}: {:?}", importer.name, importer.data.configuration);

    service.update_start(&importer.name, None).await?;

    // record timestamp before processing, so that we can use it as "since" marker
    let last_run = OffsetDateTime::now_utc();

    log::info!("Starting run: {}", importer.name);

    let context = ServiceRunContext::new(service.clone(), importer.name.clone(), cancel);

    let (last_error, report, continuation) = match runner
        .run_once(
            context,
            importer.data.configuration,
            importer.data.last_success,
            importer.data.continuation,
        )
        .await
    {
        Ok(RunOutput {
            report,
            continuation,
        }) => (None, Some(report), continuation),
        Err(ScannerError::Normal {
            err,
            output: RunOutput {
                report,
                continuation,
            },
        }) => (Some(err.to_string()), Some(report), continuation),
        Err(ScannerError::Critical(err)) => (Some(err.to_string()), None, None),
    };

    log::info!("Import run complete: {last_error:?}");

    service
        .update_finish(
            &importer.name,
            None,
            last_run,
            last_error,
            continuation,
            report.and_then(|report| serde_json::to_value(report).ok()),
        )
        .await?;

    Ok(())
}

async fn reap(importers: &[Importer], service: &ImporterService) -> anyhow::Result<()> {
    for importer in importers
        .iter()
        .filter(|i| i.data.state == State::Running && !i.is_running())
    {
        log::info!(
            "Reaping stale importer job: {} (since: {})",
            importer.name,
            importer.data.last_change
        );
        service
            .update_finish(
                &importer.name,
                None,
                importer.data.last_run.unwrap_or(importer.data.last_change),
                Some("Import aborted".into()),
                None,
                None,
            )
            .await?;
    }
    Ok(())
}
