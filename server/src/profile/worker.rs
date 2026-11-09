use crate::profile::spawn_db_check;
use bytesize::ByteSize;
use futures::{FutureExt, future::LocalBoxFuture};
use std::{num::NonZeroUsize, process::ExitCode};
use trustify_common::{
    config::{Database, DatabaseReadOnly, parse_concurrency},
    db::{self, change::ChangeBroadcaster},
};
use trustify_infrastructure::{Infrastructure, InfrastructureConfig, InitContext};
use trustify_module_correlation::{
    extractor::worker::run_extraction_workers,
    service::tuning::{DEFAULT_MATCH_BATCH, WorkerConfig, parse_work_mem},
};
use trustify_module_notification::config::NotificationConfig;

/// Settings of the correlation worker, shared by the API server and the worker.
#[derive(clap::Args, Debug, Clone)]
pub struct CorrelationWorkerArgs {
    /// The `work_mem` of the correlation worker's transactions (e.g. `256MiB`).
    ///
    /// When unset (the default), the database's setting applies.
    #[arg(long, env = "TRUSTD_CORRELATION_WORK_MEM", value_parser = parse_work_mem)]
    pub correlation_work_mem: Option<ByteSize>,

    /// The number of correlation workers of this instance, `0` for one per available CPU.
    ///
    /// Workers of all instances process different advisories, SBOMs and verdicts in parallel.
    #[arg(long, env = "TRUSTD_CORRELATION_WORKERS", default_value = "1", value_parser = parse_concurrency)]
    pub correlation_workers: NonZeroUsize,

    /// The number of matches of an SBOM held in memory before their evidence is written.
    ///
    /// Bounds the memory of extracting an SBOM. The matches of a node are written together, so a
    /// node with more matches exceeds it.
    #[arg(
        long,
        env = "TRUSTD_CORRELATION_MATCH_BATCH",
        default_value_t = DEFAULT_MATCH_BATCH,
        value_parser = parse_match_batch
    )]
    pub correlation_match_batch: usize,
}

/// Parse the matches held before writing, at least one.
fn parse_match_batch(value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(0) => Err("must be at least 1".to_string()),
        Ok(value) => Ok(value),
        Err(err) => Err(err.to_string()),
    }
}

impl From<CorrelationWorkerArgs> for WorkerConfig {
    fn from(args: CorrelationWorkerArgs) -> Self {
        Self {
            workers: args.correlation_workers,
            work_mem: args.correlation_work_mem,
            match_batch: args.correlation_match_batch,
        }
    }
}

/// A background job the worker can run.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Job {
    /// Extract correlation evidence, refresh outdated documents and compute verdicts
    Correlation,
}

/// Run background jobs, without serving the API
#[derive(clap::Args, Debug)]
pub struct Run {
    /// The jobs to run (comma-separated). Defaults to all jobs.
    #[arg(
        long = "job",
        env = "TRUSTD_WORKER_JOBS",
        value_delimiter = ',',
        default_value = "correlation"
    )]
    pub jobs: Vec<Job>,

    /// Correlation worker settings
    #[command(flatten)]
    pub correlation: CorrelationWorkerArgs,

    // flattened commands must go last
    //
    /// Notification configuration, for the change events that wake up the jobs
    #[command(flatten)]
    pub notification: NotificationConfig,

    /// Database configuration
    #[command(flatten)]
    pub database: Database,

    /// Read-only database configuration (optional, falls back to primary database)
    #[command(flatten)]
    pub database_ro: DatabaseReadOnly,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

const SERVICE_ID: &str = "trustify-worker";

/// What a job can access.
#[derive(Clone)]
pub struct JobContext {
    /// The primary database.
    pub db_rw: db::ReadWrite,
    /// The read-only database, which may be a replica lagging behind the primary.
    pub db_ro: db::ReadOnly,
    /// Change events of the primary database.
    pub broadcaster: ChangeBroadcaster,
}

type Task = LocalBoxFuture<'static, anyhow::Result<()>>;

struct InitData {
    context: JobContext,
    jobs: Vec<Job>,
    correlation: WorkerConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        // logging is only active once the infrastructure run method has been called
        Infrastructure::from(self.infra.clone())
            .run(
                SERVICE_ID,
                |context| async move { InitData::new(context, self).await },
                |context| async move { context.init_data.run().await },
            )
            .await?;

        Ok(ExitCode::SUCCESS)
    }
}

impl InitData {
    async fn new(context: InitContext, run: Run) -> anyhow::Result<Self> {
        let db = db::Database::new(&run.database).await?;
        let ro_config = run.database_ro.to_database_config(&run.database)?;
        let db_ro = db::Database::new(&ro_config).await?;

        context
            .health
            .readiness
            .register("database", spawn_db_check(db.clone())?)
            .await;
        context
            .health
            .readiness
            .register("database-ro", spawn_db_check(db_ro.clone())?)
            .await;

        let db_rw = db::ReadWrite::new(db);
        let broadcaster = ChangeBroadcaster::new(
            &db_rw,
            *run.notification.change_log_retention,
            *run.notification.change_log_poll_interval,
            *run.notification.change_log_cleanup_interval,
        )?;

        let mut jobs = run.jobs;
        jobs.sort_by_key(|job| *job as u8);
        jobs.dedup();

        Ok(Self {
            context: JobContext {
                db_rw,
                db_ro: db::ReadOnly::new(db_ro),
                broadcaster,
            },
            jobs,
            correlation: run.correlation.into(),
        })
    }

    fn tasks(&self) -> Vec<Task> {
        self.jobs
            .iter()
            .map(|job| match job {
                Job::Correlation => {
                    correlation_task(self.context.clone(), self.correlation.clone())
                }
            })
            .collect()
    }

    async fn run(self) -> anyhow::Result<()> {
        let tasks = self.tasks();
        if tasks.is_empty() {
            anyhow::bail!("no jobs to run");
        }

        let (result, _, _) = futures::future::select_all(tasks).await;

        tracing::info!("one of the jobs returned, exiting: {result:?}");

        result
    }
}

/// The correlation worker task.
pub fn correlation_task(context: JobContext, config: WorkerConfig) -> Task {
    async move { run_extraction_workers(context.broadcaster, context.db_rw, config).await }
        .boxed_local()
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::{Args, Command, FromArgMatches};
    use std::thread::available_parallelism;
    use test_context::test_context;
    use trustify_test_context::TrustifyContext;

    /// Zero workers mean one per available CPU.
    #[test]
    fn workers_per_cpu() -> anyhow::Result<()> {
        let args = CorrelationWorkerArgs::from_arg_matches(
            &CorrelationWorkerArgs::augment_args(Command::new("cmd")).get_matches_from([
                "cmd",
                "--correlation-workers",
                "0",
            ]),
        )?;

        assert_eq!(args.correlation_workers, available_parallelism()?);
        Ok(())
    }

    #[test_context(TrustifyContext)]
    #[test_log::test(tokio::test)]
    async fn runs_the_selected_jobs(ctx: &TrustifyContext) -> anyhow::Result<()> {
        let port = ctx.port.to_string();
        let run =
            Run::from_arg_matches(&Run::augment_args(Command::new("cmd")).get_matches_from([
                "cmd",
                "--db-name",
                "test",
                "--db-port",
                &port,
                "--job",
                "correlation,correlation",
                "--correlation-workers",
                "3",
            ]))?;
        let init = InitData::new(InitContext::default(), run).await?;

        assert_eq!(init.jobs, vec![Job::Correlation]);
        assert_eq!(
            init.correlation,
            WorkerConfig {
                workers: NonZeroUsize::new(3).ok_or_else(|| anyhow::anyhow!("zero"))?,
                work_mem: None,
                match_batch: DEFAULT_MATCH_BATCH,
            }
        );
        assert_eq!(init.tasks().len(), 1);
        Ok(())
    }
}
