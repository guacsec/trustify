use crate::profile::spawn_db_check;
use futures::FutureExt;
use std::{path::PathBuf, process::ExitCode};
use trustify_common::{
    config::Database,
    db::{
        self,
        pagination_cache::{PaginationCache, PaginationConfig},
    },
};
use trustify_infrastructure::{Infrastructure, InfrastructureConfig, InitContext};
use trustify_module_importer::server::importer;
use trustify_module_storage::{config::StorageConfig, service::dispatch::DispatchBackend};

/// Run the importer server
#[derive(clap::Args, Debug)]
pub struct Run {
    /// Enable read-only mode, suspending all importer runs
    #[arg(long, env = "TRUSTD_READ_ONLY")]
    pub read_only: bool,

    /// The importer working directory
    #[arg(long, id = "working_dir", env = "IMPORTER_WORKING_DIR")]
    pub working_dir: Option<PathBuf>,

    /// The max number of concurrent importer runs
    #[arg(
        long,
        id = "concurrency",
        env = "IMPORTER_CONCURRENCY",
        default_value = "1"
    )]
    pub concurrency: usize,

    // flattened commands must go last
    //
    /// Pagination configuration
    #[command(flatten)]
    pub pagination: PaginationConfig,

    /// Database configuration
    #[command(flatten)]
    pub database: Database,

    /// Location of the storage
    #[command(flatten)]
    pub storage: StorageConfig,

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

const SERVICE_ID: &str = "trustify-importer";

struct InitData {
    db: db::Database,
    cache: PaginationCache,
    storage: DispatchBackend,
    working_dir: Option<PathBuf>,
    concurrency: usize,
    read_only: bool,
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

        context
            .health
            .readiness
            .register("database", spawn_db_check(db.clone())?)
            .await;

        let storage = run.storage.into_storage(false).await?;

        Ok(InitData {
            db,
            cache: run.pagination.into_cache(),
            storage,
            working_dir: run.working_dir,
            concurrency: run.concurrency,
            read_only: run.read_only,
        })
    }

    async fn run(self) -> anyhow::Result<()> {
        let db = self.db;
        let storage = self.storage;

        let importer = async {
            importer(
                db,
                self.cache,
                storage,
                self.working_dir,
                None, // Running the importer, we don't need an analysis graph update
                self.concurrency,
                self.read_only,
            )
            .await
        }
        .boxed_local();

        let tasks = vec![importer];

        let (result, _, _) = futures::future::select_all(tasks).await;

        log::info!("one of the server tasks returned, exiting: {result:?}");

        result
    }
}
